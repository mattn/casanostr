#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cJSON.h"
#include "civetweb.h"
#include "nostr.h"
#include "store.h"

#ifndef VERSION
#define VERSION "dev"
#endif

#define RELAY_NAME "casanostr"
#define RELAY_DESCRIPTION "a nostr relay written in C"
#define RELAY_SOFTWARE "https://github.com/mattn/casanostr"

#define MAX_MESSAGE_SIZE (512 * 1024)
#define MAX_SUBS 32

struct sub {
  char id[65];
  cJSON *filters; /* array of filter objects */
  struct sub *next;
};

struct client {
  struct mg_connection *conn;
  struct sub *subs;
  char *buf; /* websocket message reassembly */
  size_t len;
  struct client *next;
};

static struct client *g_clients;
static pthread_mutex_t g_clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t g_stop;

/* --- senders ------------------------------------------------------------ */

static void
send_text(struct mg_connection *conn, const char *s, size_t n) {
  mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, s, n);
}

static void
send_json(struct mg_connection *conn, cJSON *j) {
  char *s = cJSON_PrintUnformatted(j);
  if (s != NULL) {
    send_text(conn, s, strlen(s));
    free(s);
  }
  cJSON_Delete(j);
}

static void
send_notice(struct mg_connection *conn, const char *msg) {
  cJSON *j = cJSON_CreateArray();
  cJSON_AddItemToArray(j, cJSON_CreateString("NOTICE"));
  cJSON_AddItemToArray(j, cJSON_CreateString(msg));
  send_json(conn, j);
}

static void
send_ok(struct mg_connection *conn, const char *id, bool ok, const char *msg) {
  cJSON *j = cJSON_CreateArray();
  cJSON_AddItemToArray(j, cJSON_CreateString("OK"));
  cJSON_AddItemToArray(j, cJSON_CreateString(id));
  cJSON_AddItemToArray(j, cJSON_CreateBool(ok));
  cJSON_AddItemToArray(j, cJSON_CreateString(msg));
  send_json(conn, j);
}

static void
send_closed(struct mg_connection *conn, const char *subid, const char *msg) {
  cJSON *j = cJSON_CreateArray();
  cJSON_AddItemToArray(j, cJSON_CreateString("CLOSED"));
  cJSON_AddItemToArray(j, cJSON_CreateString(subid));
  cJSON_AddItemToArray(j, cJSON_CreateString(msg));
  send_json(conn, j);
}

static void
send_eose(struct mg_connection *conn, const char *subid) {
  cJSON *j = cJSON_CreateArray();
  cJSON_AddItemToArray(j, cJSON_CreateString("EOSE"));
  cJSON_AddItemToArray(j, cJSON_CreateString(subid));
  send_json(conn, j);
}

/* ["EVENT","<subid>",<raw>] spliced without reparsing the stored JSON */
static void
send_stored_event(struct mg_connection *conn, const char *subid,
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

  pthread_mutex_lock(&g_clients_mutex);
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
    pthread_mutex_unlock(&g_clients_mutex);
    sub_free(sub);
    return false;
  }
  sub->next = c->subs;
  c->subs = sub;
  pthread_mutex_unlock(&g_clients_mutex);
  return true;
}

static void
client_del_sub(struct client *c, const char *subid) {
  struct sub **p;
  pthread_mutex_lock(&g_clients_mutex);
  for (p = &c->subs; *p != NULL; p = &(*p)->next) {
    if (strcmp((*p)->id, subid) == 0) {
      struct sub *old = *p;
      *p = old->next;
      sub_free(old);
      break;
    }
  }
  pthread_mutex_unlock(&g_clients_mutex);
}

static void
broadcast_event(const cJSON *ev, const char *raw) {
  struct client *c;
  struct sub *s;
  pthread_mutex_lock(&g_clients_mutex);
  for (c = g_clients; c != NULL; c = c->next)
    for (s = c->subs; s != NULL; s = s->next)
      if (nostr_filters_match(s->filters, ev))
        send_stored_event(c->conn, s->id, raw);
  pthread_mutex_unlock(&g_clients_mutex);
}

/* --- message handling --------------------------------------------------- */

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
  raw = cJSON_PrintUnformatted((cJSON *)ev);
  if (raw == NULL) {
    send_ok(c->conn, id, false, "error: out of memory");
    return;
  }
  r = store_event(ev, raw);
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
  if (rc->nseen == rc->cap) {
    rc->cap = rc->cap ? rc->cap * 2 : 64;
    rc->seen = realloc(rc->seen, sizeof *rc->seen * rc->cap);
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

  filters = cJSON_CreateArray();
  n = cJSON_GetArraySize((cJSON *)msg);
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
  } else if (strcmp(cmd->valuestring, "CLOSE") == 0) {
    const cJSON *jsid = cJSON_GetArrayItem(msg, 1);
    if (cJSON_IsString(jsid) && valid_subid(jsid->valuestring))
      client_del_sub(c, jsid->valuestring);
  } else {
    send_notice(c->conn, "unknown command");
  }
  cJSON_Delete(msg);
}

/* --- civetweb handlers -------------------------------------------------- */

static int
ws_connect_handler(const struct mg_connection *conn, void *ud) {
  struct client *c = calloc(1, sizeof *c);
  (void)ud;
  if (c == NULL) return 1; /* refuse */
  c->conn = (struct mg_connection *)conn;
  mg_set_user_connection_data((struct mg_connection *)conn, c);
  pthread_mutex_lock(&g_clients_mutex);
  c->next = g_clients;
  g_clients = c;
  pthread_mutex_unlock(&g_clients_mutex);
  return 0;
}

static void
ws_ready_handler(struct mg_connection *conn, void *ud) {
  (void)conn;
  (void)ud;
}

static int
ws_data_handler(struct mg_connection *conn, int bits, char *data, size_t len,
                void *ud) {
  struct client *c = mg_get_user_connection_data(conn);
  int op = bits & 0x0f;
  char *nb;
  (void)ud;

  if (c == NULL) return 0;
  switch (op) {
  case MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE:
    return 0;
  case MG_WEBSOCKET_OPCODE_PING:
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_PONG, data, len);
    return 1;
  case MG_WEBSOCKET_OPCODE_PONG:
    return 1;
  case MG_WEBSOCKET_OPCODE_TEXT:
  case MG_WEBSOCKET_OPCODE_CONTINUATION:
    break;
  default:
    return 1; /* ignore binary frames */
  }

  if (c->len + len > MAX_MESSAGE_SIZE) {
    send_notice(conn, "error: message too large");
    return 0;
  }
  nb = realloc(c->buf, c->len + len);
  if (nb == NULL) return 0;
  memcpy(nb + c->len, data, len);
  c->buf = nb;
  c->len += len;
  if (bits & 0x80) { /* FIN */
    process_message(c, c->buf, c->len);
    free(c->buf);
    c->buf = NULL;
    c->len = 0;
  }
  return 1;
}

static void
ws_close_handler(const struct mg_connection *conn, void *ud) {
  struct client *c = mg_get_user_connection_data(conn);
  struct client **p;
  (void)ud;
  if (c == NULL) return;
  pthread_mutex_lock(&g_clients_mutex);
  for (p = &g_clients; *p != NULL; p = &(*p)->next) {
    if (*p == c) {
      *p = c->next;
      break;
    }
  }
  pthread_mutex_unlock(&g_clients_mutex);
  while (c->subs != NULL) {
    struct sub *s = c->subs;
    c->subs = s->next;
    sub_free(s);
  }
  free(c->buf);
  free(c);
}

static int
http_handler(struct mg_connection *conn, void *ud) {
  const struct mg_request_info *ri = mg_get_request_info(conn);
  const char *accept = mg_get_header(conn, "Accept");
  (void)ud;

  if (strcmp(ri->local_uri, "/") != 0) {
    mg_send_http_error(conn, 404, "%s", "not found");
    return 404;
  }
  if (accept != NULL && strstr(accept, "application/nostr+json") != NULL) {
    /* NIP-11 relay information document */
    static const int nips[] = {1, 9, 11};
    cJSON *j = cJSON_CreateObject();
    char *s;
    cJSON_AddStringToObject(j, "name", RELAY_NAME);
    cJSON_AddStringToObject(j, "description", RELAY_DESCRIPTION);
    cJSON_AddStringToObject(j, "software", RELAY_SOFTWARE);
    cJSON_AddStringToObject(j, "version", VERSION);
    cJSON_AddItemToObject(j, "supported_nips", cJSON_CreateIntArray(nips, 3));
    s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: application/nostr+json\r\n"
              "Access-Control-Allow-Origin: *\r\n"
              "Content-Length: %lu\r\n"
              "Connection: close\r\n\r\n%s",
              (unsigned long)strlen(s), s);
    free(s);
  } else {
    static const char body[] =
        RELAY_NAME " - " RELAY_DESCRIPTION "\n"
        "connect with a nostr client via ws://\n";
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/plain; charset=utf-8\r\n"
              "Content-Length: %lu\r\n"
              "Connection: close\r\n\r\n%s",
              (unsigned long)(sizeof body - 1), body);
  }
  return 200;
}

/* --- main --------------------------------------------------------------- */

static void
on_signal(int sig) {
  (void)sig;
  g_stop = 1;
}

int
main(int argc, char **argv) {
  int opt, port = 7447;
  const char *dbpath = getenv("DATABASE_URL");
  char ports[16];
  struct mg_callbacks callbacks;
  struct mg_context *ctx;

  while ((opt = getopt(argc, argv, "p:d:vh")) != -1) {
    switch (opt) {
    case 'p':
      port = atoi(optarg);
      break;
    case 'd':
      dbpath = optarg;
      break;
    case 'v':
      printf("%s %s\n", RELAY_NAME, VERSION);
      return 0;
    case 'h':
    default:
      fprintf(stderr, "usage: %s [-p port] [-d dbfile|postgres://...]\n",
              RELAY_NAME);
      return opt == 'h' ? 0 : 1;
    }
  }
  if (dbpath == NULL) dbpath = "casanostr.db";

  if (!store_init(dbpath)) return 1;

  snprintf(ports, sizeof ports, "%d", port);
  const char *options[] = {
      "listening_ports",      ports,
      "num_threads",          "16",
      "websocket_timeout_ms", "3600000",
      NULL};
  mg_init_library(0);
  memset(&callbacks, 0, sizeof callbacks);
  ctx = mg_start(&callbacks, NULL, options);
  if (ctx == NULL) {
    fprintf(stderr, "%s: failed to start server on port %d\n", RELAY_NAME,
            port);
    return 1;
  }
  mg_set_request_handler(ctx, "/", http_handler, NULL);
  mg_set_websocket_handler(ctx, "/", ws_connect_handler, ws_ready_handler,
                           ws_data_handler, ws_close_handler, NULL);

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  printf("%s %s listening on port %d (db: %s)\n", RELAY_NAME, VERSION, port,
         dbpath);

  while (!g_stop) usleep(200 * 1000);

  mg_stop(ctx);
  mg_exit_library();
  store_close();
  return 0;
}
