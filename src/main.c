#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "net.h"
#include "nostr.h"
#include "store.h"

#ifndef VERSION
#define VERSION "dev"
#endif

#define RELAY_NAME "casanostr"
#define RELAY_DESCRIPTION "a nostr relay written in C"
#define RELAY_SOFTWARE "https://github.com/mattn/casanostr"
#define RELAY_ICON \
  "https://raw.githubusercontent.com/mattn/casanostr/main/casanostr.png"

#define MAX_MESSAGE_SIZE (512 * 1024)
#define MAX_SUBS 32
#define MAX_LIMIT 1000
/* NIP-40 / created_at sanity: allow this much clock skew into the future */
#define CREATED_AT_UPPER_LIMIT 900
/* each filter costs one query on REQ and one match per stored event
 * afterwards, so an uncapped list turns a single message into unbounded work */
#define MAX_FILTERS 32

/* NIP-13: minimum proof of work demanded of incoming events; 0 disables it */
static int g_min_pow;
/* NIP-42 / NIP-62: this relay's public URL, used to tell a request aimed at
 * us from one aimed elsewhere. Empty means we cannot tell, so NIP-62 only
 * honours ALL_RELAYS. */
static const char *g_service_url = "";

struct sub {
  char id[65];
  cJSON *filters; /* array of filter objects */
  struct sub *next;
};

struct client {
  struct net_conn *conn;
  struct sub *subs;
  char challenge[33]; /* NIP-42 challenge, sent once the connection is up */
  char authed[65];    /* NIP-42 authenticated pubkey; empty until AUTH */
  struct client *next;
};

/* everything runs on the net.c event loop thread, so the client list and
 * the per-client state need no locking */
static struct client *g_clients;

/* --- senders ------------------------------------------------------------ */

static void
send_text(struct net_conn *conn, const char *s, size_t n) {
  net_ws_send_text(conn, s, n);
}

static void
send_json(struct net_conn *conn, cJSON *j) {
  char *s = cJSON_PrintUnformatted(j);
  if (s != NULL) {
    send_text(conn, s, strlen(s));
    free(s);
  }
  cJSON_Delete(j);
}

static void
send_notice(struct net_conn *conn, const char *msg) {
  cJSON *j = cJSON_CreateArray();
  cJSON_AddItemToArray(j, cJSON_CreateString("NOTICE"));
  cJSON_AddItemToArray(j, cJSON_CreateString(msg));
  send_json(conn, j);
}

static void
send_ok(struct net_conn *conn, const char *id, bool ok, const char *msg) {
  cJSON *j = cJSON_CreateArray();
  cJSON_AddItemToArray(j, cJSON_CreateString("OK"));
  cJSON_AddItemToArray(j, cJSON_CreateString(id));
  cJSON_AddItemToArray(j, cJSON_CreateBool(ok));
  cJSON_AddItemToArray(j, cJSON_CreateString(msg));
  send_json(conn, j);
}

static void
send_closed(struct net_conn *conn, const char *subid, const char *msg) {
  cJSON *j = cJSON_CreateArray();
  cJSON_AddItemToArray(j, cJSON_CreateString("CLOSED"));
  cJSON_AddItemToArray(j, cJSON_CreateString(subid));
  cJSON_AddItemToArray(j, cJSON_CreateString(msg));
  send_json(conn, j);
}

/* NIP-42: a challenge only has to be unpredictable and single-use, so take
 * it straight from the system CSPRNG and hex-encode it. */
static void
make_challenge(char *out, size_t outlen) {
  static const char hex[] = "0123456789abcdef";
  unsigned char buf[16];
  FILE *fp = fopen("/dev/urandom", "rb");
  size_t i, n = (outlen - 1) / 2;
  if (n > sizeof buf) n = sizeof buf;
  if (fp == NULL || fread(buf, 1, n, fp) != n) {
    /* no entropy source: fall back to something merely unique so the
     * connection still works, and let AUTH be best effort */
    for (i = 0; i < n; i++) buf[i] = (unsigned char)(rand() >> 7);
  }
  if (fp != NULL) fclose(fp);
  for (i = 0; i < n; i++) {
    out[i * 2] = hex[buf[i] >> 4];
    out[i * 2 + 1] = hex[buf[i] & 0x0f];
  }
  out[n * 2] = '\0';
}

/* NIP-42: ["AUTH","<challenge>"] */
static void
send_auth(struct net_conn *conn, const char *challenge) {
  cJSON *j = cJSON_CreateArray();
  cJSON_AddItemToArray(j, cJSON_CreateString("AUTH"));
  cJSON_AddItemToArray(j, cJSON_CreateString(challenge));
  send_json(conn, j);
}

static void
send_eose(struct net_conn *conn, const char *subid) {
  cJSON *j = cJSON_CreateArray();
  cJSON_AddItemToArray(j, cJSON_CreateString("EOSE"));
  cJSON_AddItemToArray(j, cJSON_CreateString(subid));
  send_json(conn, j);
}

/* ["EVENT","<subid>",<raw>] spliced without reparsing the stored JSON */
static void
send_stored_event(struct net_conn *conn, const char *subid,
                  const char *raw) {
  size_t n = strlen(subid) + strlen(raw) + 16;
  char *s = malloc(n);
  int m;
  if (s == NULL) return;
  m = snprintf(s, n, "[\"EVENT\",\"%s\",%s]", subid, raw);
  send_text(conn, s, (size_t)m);
  free(s);
}

/* subscription ids are spliced into JSON directly, so restrict them to
 * printable ASCII without quote and backslash */
static bool
valid_subid(const char *s) {
  size_t n = strlen(s);
  if (n < 1 || n > 64) return false;
  for (; *s != '\0'; s++)
    if (*s < 0x20 || *s > 0x7e || *s == '"' || *s == '\\') return false;
  return true;
}

/* --- subscriptions ------------------------------------------------------ */

static void
sub_free(struct sub *sub) {
  cJSON_Delete(sub->filters);
  free(sub);
}

/* takes ownership of filters; false when the client has too many subs */
static bool
client_set_sub(struct client *c, const char *subid, cJSON *filters) {
  struct sub **p, *sub;
  int count = 0;

  sub = calloc(1, sizeof *sub);
  if (sub == NULL) {
    cJSON_Delete(filters);
    return false;
  }
  snprintf(sub->id, sizeof sub->id, "%s", subid);
  sub->filters = filters;

  for (p = &c->subs; *p != NULL;) {
    if (strcmp((*p)->id, subid) == 0) {
      struct sub *old = *p;
      *p = old->next;
      sub_free(old);
    } else {
      count++;
      p = &(*p)->next;
    }
  }
  if (count >= MAX_SUBS) {
    sub_free(sub);
    return false;
  }
  sub->next = c->subs;
  c->subs = sub;
  return true;
}

static void
client_del_sub(struct client *c, const char *subid) {
  struct sub **p;
  for (p = &c->subs; *p != NULL; p = &(*p)->next) {
    if (strcmp((*p)->id, subid) == 0) {
      struct sub *old = *p;
      *p = old->next;
      sub_free(old);
      break;
    }
  }
}

/* NIP-17/59: a gift wrap is addressed to one recipient, so only hand it to a
 * connection that has authenticated as a pubkey the event is p-tagged with.
 * An unauthenticated connection sees no gift wraps at all. */
static bool
may_see_gift_wrap(const char *authed, const cJSON *ev) {
  const cJSON *kind = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "kind");
  const cJSON *tags, *t;
  int k;

  if (!cJSON_IsNumber(kind)) return true;
  k = (int)kind->valuedouble;
  if (k != 1059 && k != 21059) return true;
  if (authed[0] == '\0') return false;

  tags = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "tags");
  for (t = cJSON_IsArray(tags) ? tags->child : NULL; t != NULL; t = t->next) {
    const cJSON *tn, *tv;
    if (!cJSON_IsArray(t)) continue;
    tn = t->child;
    tv = tn != NULL ? tn->next : NULL;
    if (cJSON_IsString(tn) && cJSON_IsString(tv) &&
        strcmp(tn->valuestring, "p") == 0 &&
        strcmp(tv->valuestring, authed) == 0)
      return true;
  }
  return false;
}

/* Sending only appends to the recipient's output buffer (net.c flushes it
 * without blocking), so a client that stops reading cannot stall anyone —
 * it just accumulates output until net.c drops it. */
static void
broadcast_event(const cJSON *ev, const char *raw) {
  struct client *c;
  struct sub *s;

  for (c = g_clients; c != NULL; c = c->next) {
    if (!may_see_gift_wrap(c->authed, ev)) continue;
    for (s = c->subs; s != NULL; s = s->next) {
      if (!nostr_filters_match(s->filters, ev)) continue;
      send_stored_event(c->conn, s->id, raw);
    }
  }
}

/* --- message handling --------------------------------------------------- */

static int
kind_of(const cJSON *ev) {
  const cJSON *k = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "kind");
  return cJSON_IsNumber(k) ? (int)k->valuedouble : -1;
}

/* NIP-62: relay URLs are compared ignoring a trailing slash, since clients
 * and operators disagree about writing one. */
static bool
same_relay_url(const char *a, const char *b) {
  size_t la = strlen(a), lb = strlen(b);
  while (la > 0 && a[la - 1] == '/') la--;
  while (lb > 0 && b[lb - 1] == '/') lb--;
  return la == lb && la > 0 && strncmp(a, b, la) == 0;
}

/* NIP-62: does this kind-62 event ask *this* relay to forget the author? */
static bool
vanish_targets_us(const cJSON *ev) {
  const cJSON *tags = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "tags");
  const cJSON *t;
  for (t = cJSON_IsArray(tags) ? tags->child : NULL; t != NULL; t = t->next) {
    const cJSON *tn, *tv;
    if (!cJSON_IsArray(t)) continue;
    tn = t->child;
    tv = tn != NULL ? tn->next : NULL;
    if (!cJSON_IsString(tn) || !cJSON_IsString(tv)) continue;
    if (strcmp(tn->valuestring, "relay") != 0) continue;
    if (strcmp(tv->valuestring, "ALL_RELAYS") == 0) return true;
    if (g_service_url[0] != '\0' &&
        same_relay_url(tv->valuestring, g_service_url))
      return true;
  }
  return false;
}

/* NIP-70: the marker is the single-element tag ["-"]; a longer tag whose
 * first element happens to be "-" is an ordinary tag. */
static bool
is_protected(const cJSON *ev) {
  const cJSON *tags = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "tags");
  const cJSON *t;
  for (t = cJSON_IsArray(tags) ? tags->child : NULL; t != NULL; t = t->next) {
    const cJSON *tn;
    if (!cJSON_IsArray(t) || cJSON_GetArraySize((cJSON *)t) != 1) continue;
    tn = t->child;
    if (cJSON_IsString(tn) && strcmp(tn->valuestring, "-") == 0) return true;
  }
  return false;
}

/* NIP-13: difficulty is the number of leading zero bits of the event id.
 * Only the id is checked; whether a nonce tag commits to the same target is
 * the publishing client's business. */
static int
pow_difficulty(const char *id_hex) {
  int bits = 0;
  size_t i;
  for (i = 0; i < 64; i++) {
    int c = id_hex[i];
    int v = c <= '9' ? c - '0' : c - 'a' + 10;
    if (v == 0) {
      bits += 4;
      continue;
    }
    if (v < 2) bits += 3;
    else if (v < 4) bits += 2;
    else if (v < 8) bits += 1;
    break;
  }
  return bits;
}

static void
process_event(struct client *c, const cJSON *msg) {
  const cJSON *ev = cJSON_GetArrayItem((cJSON *)msg, 1);
  const cJSON *jid =
      ev != NULL ? cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "id") : NULL;
  const char *id = cJSON_IsString(jid) ? jid->valuestring : "";
  const char *err;
  char *raw;
  store_result r;

  err = nostr_event_validate(ev);
  if (err != NULL) {
    send_ok(c->conn, id, false, err);
    return;
  }
  {
    const cJSON *jca = cJSON_GetObjectItemCaseSensitive((cJSON *)ev,
                                                        "created_at");
    const char *exp = nostr_tag_value(ev, "expiration");
    long long now = (long long)time(NULL);
    if (cJSON_IsNumber(jca) &&
        (long long)jca->valuedouble > now + CREATED_AT_UPPER_LIMIT) {
      send_ok(c->conn, id, false, "invalid: created_at is in the future");
      return;
    }
    if (exp != NULL) {
      long long e = atoll(exp);
      if (e > 0 && e <= now) {
        send_ok(c->conn, id, false, "invalid: event has already expired");
        return;
      }
    }
  }
  if (g_min_pow > 0) {
    int d = pow_difficulty(id);
    if (d < g_min_pow) {
      char m[80];
      snprintf(m, sizeof m, "pow: difficulty %d is less than %d", d,
               g_min_pow);
      send_ok(c->conn, id, false, m);
      return;
    }
  }
  /* NIP-70: a bare ["-"] tag means only the author may publish this event,
   * so it needs an authenticated connection belonging to that pubkey */
  if (is_protected(ev)) {
    const cJSON *pk = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "pubkey");
    bool owned;
    owned = c->authed[0] != '\0' && cJSON_IsString(pk) &&
            strcmp(c->authed, pk->valuestring) == 0;
    if (!owned) {
      /* re-offer a challenge so the client can authenticate and retry */
      if (c->challenge[0] == '\0')
        make_challenge(c->challenge, sizeof c->challenge);
      send_auth(c->conn, c->challenge);
      send_ok(c->conn, id, false, "auth-required: this event is protected");
      return;
    }
  }
  /* the same shape a stored row rebuilds into, so live delivery and a
   * later query hand the client identical bytes */
  /* NIP-62: honour the request before storing it, so the vanish cannot be
   * undone by the request's own row surviving a later replay. */
  if (kind_of(ev) == 62) {
    const cJSON *pk = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "pubkey");
    const cJSON *ca = cJSON_GetObjectItemCaseSensitive((cJSON *)ev,
                                                       "created_at");
    if (vanish_targets_us(ev) && cJSON_IsString(pk) && cJSON_IsNumber(ca) &&
        !store_vanish(pk->valuestring, (long long)ca->valuedouble)) {
      send_ok(c->conn, id, false, "error: failed to vanish events");
      return;
    }
  }
  raw = nostr_event_json(ev);
  if (raw == NULL) {
    send_ok(c->conn, id, false, "error: out of memory");
    return;
  }
  r = store_event(ev);
  switch (r) {
  case STORE_DUPLICATE:
    send_ok(c->conn, id, true, "duplicate: already have this event");
    break;
  case STORE_ERROR:
    send_ok(c->conn, id, false, "error: database failure");
    break;
  default:
    send_ok(c->conn, id, true, "");
    break;
  }
  if (r == STORE_NEW || r == STORE_EPHEMERAL) broadcast_event(ev, raw);
  free(raw);
}

/* Cheap pre-check so the common event does not get parsed twice: only a
 * gift wrap can be withheld, and only those carry this kind. */
static bool
looks_like_gift_wrap(const char *raw) {
  return strstr(raw, "\"kind\":1059") != NULL ||
         strstr(raw, "\"kind\":21059") != NULL;
}

struct req_ctx {
  struct client *c;
  const char *subid;
  char (*seen)[65];
  int nseen, cap;
};

static int
req_emit(const char *id, const char *raw, void *ud) {
  struct req_ctx *rc = ud;
  int i;
  for (i = 0; i < rc->nseen; i++)
    if (strcmp(rc->seen[i], id) == 0) return 0;
  if (looks_like_gift_wrap(raw)) {
    cJSON *ev = cJSON_Parse(raw);
    bool allowed = ev == NULL || may_see_gift_wrap(rc->c->authed, ev);
    cJSON_Delete(ev);
    if (!allowed) return 0;
  }
  if (rc->nseen == rc->cap) {
    int ncap = rc->cap ? rc->cap * 2 : 64;
    void *ns = realloc(rc->seen, sizeof *rc->seen * ncap);
    if (ns == NULL) return -1; /* stop the query, do not write through NULL */
    rc->seen = ns;
    rc->cap = ncap;
  }
  snprintf(rc->seen[rc->nseen++], sizeof *rc->seen, "%s", id);
  send_stored_event(rc->c->conn, rc->subid, raw);
  return 0;
}

static void
process_req(struct client *c, const cJSON *msg) {
  const cJSON *jsid = cJSON_GetArrayItem((cJSON *)msg, 1);
  const char *subid;
  cJSON *filters;
  struct req_ctx rc = {c, NULL, NULL, 0, 0};
  int i, n;

  if (!cJSON_IsString(jsid) || !valid_subid(jsid->valuestring)) {
    send_notice(c->conn, "invalid: bad subscription id");
    return;
  }
  subid = jsid->valuestring;

  n = cJSON_GetArraySize((cJSON *)msg);
  if (n - 2 > MAX_FILTERS) {
    send_closed(c->conn, subid, "invalid: too many filters");
    return;
  }

  filters = cJSON_CreateArray();
  for (i = 2; i < n; i++) {
    const cJSON *ff = cJSON_GetArrayItem((cJSON *)msg, i);
    if (!cJSON_IsObject(ff)) {
      cJSON_Delete(filters);
      send_closed(c->conn, subid, "invalid: filter is not an object");
      return;
    }
    cJSON_AddItemToArray(filters, cJSON_Duplicate((cJSON *)ff, 1));
  }
  if (cJSON_GetArraySize(filters) == 0)
    cJSON_AddItemToArray(filters, cJSON_CreateObject());

  if (!client_set_sub(c, subid, filters)) {
    send_closed(c->conn, subid, "error: too many subscriptions");
    return;
  }

  /* Registered before the query runs: an event stored while the query is in
   * flight is too new for its result set but would have been too early for
   * the subscription the other way round, and would never arrive. The query
   * reads the caller's filters rather than the registered copy, which
   * another thread may already have replaced or freed. A client can now see
   * such an event twice and drops the repeat by id. */
  rc.subid = subid;
  if (n > 2) {
    for (i = 2; i < n; i++)
      store_query(cJSON_GetArrayItem((cJSON *)msg, i), req_emit, &rc);
  } else {
    cJSON *all = cJSON_CreateObject();
    if (all != NULL) {
      store_query(all, req_emit, &rc);
      cJSON_Delete(all);
    }
  }
  free(rc.seen);
  send_eose(c->conn, subid);
}

/* NIP-45: ["COUNT","<subid>",<filters...>] -> ["COUNT","<subid>",{"count":n}]
 * Counts per filter are summed, so an event matching several filters is
 * counted once per filter. */
static void
process_count(struct client *c, const cJSON *msg) {
  const cJSON *jsid = cJSON_GetArrayItem((cJSON *)msg, 1);
  const char *subid;
  cJSON *j, *jc;
  long long total = 0;
  int i, n;

  if (!cJSON_IsString(jsid) || !valid_subid(jsid->valuestring)) {
    send_notice(c->conn, "invalid: bad subscription id");
    return;
  }
  subid = jsid->valuestring;

  n = cJSON_GetArraySize((cJSON *)msg);
  if (n - 2 > MAX_FILTERS) {
    send_closed(c->conn, subid, "invalid: too many filters");
    return;
  }
  for (i = 2; i < n; i++) {
    const cJSON *ff = cJSON_GetArrayItem((cJSON *)msg, i);
    long long one = 0;
    if (!cJSON_IsObject(ff)) {
      send_closed(c->conn, subid, "invalid: filter is not an object");
      return;
    }
    if (!store_count(ff, &one)) {
      send_closed(c->conn, subid, "error: database failure");
      return;
    }
    total += one;
  }
  if (n <= 2) {
    cJSON *all = cJSON_CreateObject();
    bool ok = all != NULL && store_count(all, &total);
    cJSON_Delete(all);
    if (!ok) {
      send_closed(c->conn, subid, "error: database failure");
      return;
    }
  }

  j = cJSON_CreateArray();
  cJSON_AddItemToArray(j, cJSON_CreateString("COUNT"));
  cJSON_AddItemToArray(j, cJSON_CreateString(subid));
  jc = cJSON_CreateObject();
  cJSON_AddNumberToObject(jc, "count", (double)total);
  cJSON_AddItemToArray(j, jc);
  send_json(c->conn, j);
}

/* NIP-42: the client answers our challenge with a kind 22242 event whose
 * "challenge" tag is the one we sent and whose "relay" tag names this relay.
 * The signature is checked by nostr_event_validate like any other event, so
 * all that is left is to bind it to this connection. */
static void
process_auth(struct client *c, const cJSON *msg) {
  const cJSON *ev = cJSON_GetArrayItem((cJSON *)msg, 1);
  const cJSON *jid, *kind, *tags, *t, *pubkey, *created_at;
  const char *challenge = NULL, *relay = NULL;
  const char *err;
  const char *id = "";
  double now, ts;

  jid = ev != NULL ? cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "id") : NULL;
  if (cJSON_IsString(jid)) id = jid->valuestring;

  err = nostr_event_validate(ev);
  if (err != NULL) {
    send_ok(c->conn, id, false, err);
    return;
  }
  kind = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "kind");
  if (!cJSON_IsNumber(kind) || (int)kind->valuedouble != 22242) {
    send_ok(c->conn, id, false, "invalid: auth event must be kind 22242");
    return;
  }
  /* the challenge is single-use and short lived; 10 minutes is the window
   * other relays settled on */
  created_at = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "created_at");
  now = (double)time(NULL);
  ts = cJSON_IsNumber(created_at) ? created_at->valuedouble : 0;
  if (ts < now - 600 || ts > now + CREATED_AT_UPPER_LIMIT) {
    send_ok(c->conn, id, false, "invalid: auth event is not recent");
    return;
  }
  tags = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "tags");
  for (t = cJSON_IsArray(tags) ? tags->child : NULL; t != NULL; t = t->next) {
    const cJSON *tn, *tv;
    if (!cJSON_IsArray(t)) continue;
    tn = t->child;
    tv = tn != NULL ? tn->next : NULL;
    if (!cJSON_IsString(tn) || !cJSON_IsString(tv)) continue;
    if (challenge == NULL && strcmp(tn->valuestring, "challenge") == 0)
      challenge = tv->valuestring;
    else if (relay == NULL && strcmp(tn->valuestring, "relay") == 0)
      relay = tv->valuestring;
  }
  if (challenge == NULL || c->challenge[0] == '\0' ||
      strcmp(challenge, c->challenge) != 0) {
    send_ok(c->conn, id, false, "invalid: challenge does not match");
    return;
  }
  if (relay == NULL) {
    send_ok(c->conn, id, false, "invalid: auth event has no relay tag");
    return;
  }
  pubkey = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "pubkey");
  snprintf(c->authed, sizeof c->authed, "%s", pubkey->valuestring);
  /* burn the challenge so the same auth event cannot be replayed here */
  c->challenge[0] = '\0';
  send_ok(c->conn, id, true, "");
}

static void
process_message(struct client *c, const char *data, size_t len) {
  cJSON *msg = cJSON_ParseWithLength(data, len);
  const cJSON *cmd;

  if (!cJSON_IsArray(msg)) {
    cJSON_Delete(msg);
    send_notice(c->conn, "invalid: message is not a json array");
    return;
  }
  cmd = cJSON_GetArrayItem(msg, 0);
  if (!cJSON_IsString(cmd)) {
    send_notice(c->conn, "invalid: missing command");
  } else if (strcmp(cmd->valuestring, "EVENT") == 0) {
    process_event(c, msg);
  } else if (strcmp(cmd->valuestring, "REQ") == 0) {
    process_req(c, msg);
  } else if (strcmp(cmd->valuestring, "COUNT") == 0) {
    process_count(c, msg);
  } else if (strcmp(cmd->valuestring, "AUTH") == 0) {
    process_auth(c, msg);
  } else if (strcmp(cmd->valuestring, "CLOSE") == 0) {
    const cJSON *jsid = cJSON_GetArrayItem(msg, 1);
    if (cJSON_IsString(jsid) && valid_subid(jsid->valuestring))
      client_del_sub(c, jsid->valuestring);
  } else {
    send_notice(c->conn, "unknown command");
  }
  cJSON_Delete(msg);
}

/* --- event loop callbacks ----------------------------------------------- */

static void
on_ws_open(struct net_conn *conn) {
  struct client *c = calloc(1, sizeof *c);
  if (c == NULL) {
    net_conn_close(conn);
    return;
  }
  c->conn = conn;
  net_conn_set_ud(conn, c);
  c->next = g_clients;
  g_clients = c;
  /* NIP-42: offer a challenge up front so a client that wants to identify
   * itself can do so without waiting to be asked */
  make_challenge(c->challenge, sizeof c->challenge);
  send_auth(conn, c->challenge);
}

static void
on_ws_message(struct net_conn *conn, const char *data, size_t len) {
  struct client *c = net_conn_get_ud(conn);
  if (c != NULL) process_message(c, data, len);
}

static void
on_ws_overflow(struct net_conn *conn) {
  send_notice(conn, "error: message too large");
}

static void
on_ws_close(struct net_conn *conn) {
  struct client *c = net_conn_get_ud(conn);
  struct client **p;
  if (c == NULL) return;
  for (p = &g_clients; *p != NULL; p = &(*p)->next) {
    if (*p == c) {
      *p = c->next;
      break;
    }
  }
  while (c->subs != NULL) {
    struct sub *s = c->subs;
    c->subs = s->next;
    sub_free(s);
  }
  free(c);
}

static void
on_http_request(struct net_conn *conn, const char *method, const char *path,
                const char *accept) {
  (void)method;
  if (strcmp(path, "/") != 0) {
    net_http_respond(conn, 404, "text/plain; charset=utf-8", NULL,
                     "not found\n", 10);
    return;
  }
  if (strstr(accept, "application/nostr+json") != NULL) {
    /* NIP-11 relay information document.  2/4/12/15/16/20/28/33/66 need no
     * relay-side work beyond NIP-01 storage semantics, which are in: a
     * monitor's 30166 is addressable and its 10166 replaceable, and both
     * already replace and serve correctly. */
    static const int nips[] = {1,  2,  4,  9,  11, 12, 13, 15, 16, 17,
                               20, 22, 26, 28, 33, 40, 42, 45, 50, 59,
                               62, 66, 70};
    cJSON *j = cJSON_CreateObject();
    cJSON *lim = cJSON_CreateObject();
    char *s;
    cJSON_AddStringToObject(j, "name", RELAY_NAME);
    cJSON_AddStringToObject(j, "description", RELAY_DESCRIPTION);
    cJSON_AddStringToObject(j, "software", RELAY_SOFTWARE);
    cJSON_AddStringToObject(j, "version", VERSION);
    cJSON_AddStringToObject(j, "icon", RELAY_ICON);
    cJSON_AddItemToObject(j, "supported_nips",
                          cJSON_CreateIntArray(nips,
                                               sizeof nips / sizeof *nips));
    cJSON_AddNumberToObject(lim, "max_message_length", MAX_MESSAGE_SIZE);
    cJSON_AddNumberToObject(lim, "max_subscriptions", MAX_SUBS);
    cJSON_AddNumberToObject(lim, "max_filters", MAX_FILTERS);
    cJSON_AddNumberToObject(lim, "max_limit", MAX_LIMIT);
    cJSON_AddNumberToObject(lim, "max_subid_length", 64);
    cJSON_AddNumberToObject(lim, "min_pow_difficulty", g_min_pow);
    cJSON_AddNumberToObject(lim, "created_at_upper_limit",
                            CREATED_AT_UPPER_LIMIT);
    cJSON_AddBoolToObject(lim, "auth_required", false);
    cJSON_AddBoolToObject(lim, "payment_required", false);
    cJSON_AddItemToObject(j, "limitation", lim);
    s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (s == NULL) {
      net_http_respond(conn, 500, "text/plain; charset=utf-8", NULL,
                       "out of memory\n", 14);
      return;
    }
    net_http_respond(conn, 200, "application/nostr+json",
                     "Access-Control-Allow-Origin: *\r\n", s, strlen(s));
    free(s);
  } else {
    static const char body[] =
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "<meta charset=\"UTF-8\"/>\n"
        "<title>Casanostr</title>\n"
        "<style>\n"
        "#content {\n"
        "  margin: 50vh auto 0;\n"
        "  transform: translateY(-50%);\n"
        "  padding: 15px 30px;\n"
        "  text-align: center;\n"
        "}\n"
        "</style>\n"
        "<script>\n"
        "globalThis.addEventListener('DOMContentLoaded', () => {\n"
        "  const u = new URL(location.href)\n"
        "  const relayName = u.protocol.replace(/^http/, 'ws') + '//' +"
        " u.host + u.pathname.replace(/\\/$/, '')\n"
        "  document.querySelector('#relay-name').textContent = relayName\n"
        "  const m = document.querySelector('#makibishi')\n"
        "  m.setAttribute('data-content', '\xf0\x9f\xa4\x99')\n"
        "  m.setAttribute('data-relays', 'wss://relay.nostr.band,"
        "wss://nos.lol,wss://relay.damus.io,wss://yabu.me,"
        "wss://casanostr.compile-error.net,wss://nostr.compile-error.net')\n"
        "  m.setAttribute('data-allow-anonymous-reaction', true)\n"
        "  m.setAttribute('data-url', relayName)\n"
        "  globalThis.makibishi.initTarget(m)\n"
        "}, false)\n"
        "</script>\n"
        "<script src=\"https://cdn.jsdelivr.net/npm/@nikolat/makibishi@0.2.0\">"
        "</script>\n"
        "</head>\n"
        "<body>\n"
        "<div id=\"content\">\n"
        "<h1>Casanostr the Nostr relay server</h1>\n"
        "<p id=\"relay-name\"></p>\n"
        "<p><img src=\"" RELAY_ICON "\" /></p>\n"
        "<p><a href=\"" RELAY_SOFTWARE "\">" RELAY_SOFTWARE "</a></p>\n"
        "<p><span id=\"makibishi\"></span></p>\n"
        "</div>\n"
        "</body>\n"
        "</html>\n";
    net_http_respond(conn, 200, "text/html; charset=UTF-8", NULL, body,
                     sizeof body - 1);
  }
}

/* --- main --------------------------------------------------------------- */

static void
on_signal(int sig) {
  (void)sig;
  net_stop();
}

int
main(int argc, char **argv) {
  int opt, port = 7447;
  const char *dbpath = getenv("DATABASE_URL");
  static const struct net_callbacks callbacks = {
      on_ws_open, on_ws_message, on_ws_overflow, on_ws_close, on_http_request,
  };

  {
    const char *mp = getenv("MIN_POW_DIFFICULTY");
    if (mp != NULL) g_min_pow = atoi(mp);
  }

  {
    const char *u = getenv("SERVICE_URL");
    if (u != NULL) g_service_url = u;
  }

  while ((opt = getopt(argc, argv, "p:d:P:u:vh")) != -1) {
    switch (opt) {
    case 'p':
      port = atoi(optarg);
      break;
    case 'd':
      dbpath = optarg;
      break;
    case 'P':
      g_min_pow = atoi(optarg);
      break;
    case 'u':
      g_service_url = optarg;
      break;
    case 'v':
      printf("%s %s\n", RELAY_NAME, VERSION);
      return 0;
    case 'h':
    default:
      fprintf(stderr,
              "usage: %s [-p port] [-d dbfile|postgres://...] [-P min-pow]"
              " [-u service-url]\n",
              RELAY_NAME);
      return opt == 'h' ? 0 : 1;
    }
  }
  if (dbpath == NULL) dbpath = "casanostr.db";

  if (!store_init(dbpath)) return 1;

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  printf("%s %s listening on port %d (db: %s)\n", RELAY_NAME, VERSION, port,
         dbpath);

  if (!net_serve(port, &callbacks, MAX_MESSAGE_SIZE)) {
    fprintf(stderr, "%s: failed to start server on port %d\n", RELAY_NAME,
            port);
    store_close();
    return 1;
  }

  store_close();
  return 0;
}
