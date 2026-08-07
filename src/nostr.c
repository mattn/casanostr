#include "nostr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

bool
nostr_is_hex(const char *s, size_t len) {
  size_t i;
  if (s == NULL || strlen(s) != len) return false;
  for (i = 0; i < len; i++) {
    char c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

static bool
hex2bin(const char *s, unsigned char *out, size_t outlen) {
  size_t i;
  for (i = 0; i < outlen; i++) {
    if (sscanf(s + i * 2, "%2hhx", &out[i]) != 1) return false;
  }
  return true;
}

static const cJSON *
field(const cJSON *ev, const char *name) {
  return cJSON_GetObjectItemCaseSensitive((cJSON *)ev, name);
}

/* Validation reads the first member of a given name while the stored copy
 * keeps every one of them, so a second "content" would be signed as one
 * value and displayed as another by any last-wins parser. */
static bool
has_duplicate_member(const cJSON *ev) {
  const cJSON *a, *b;
  for (a = ev->child; a != NULL; a = a->next) {
    if (a->string == NULL) continue;
    for (b = a->next; b != NULL; b = b->next)
      if (b->string != NULL && strcmp(a->string, b->string) == 0) return true;
  }
  return false;
}

char *
nostr_event_canonical(const cJSON *ev) {
  const cJSON *pubkey = field(ev, "pubkey");
  const cJSON *created_at = field(ev, "created_at");
  const cJSON *kind = field(ev, "kind");
  const cJSON *tags = field(ev, "tags");
  const cJSON *content = field(ev, "content");
  cJSON *arr;
  char *s;

  if (!cJSON_IsString(pubkey) || !cJSON_IsNumber(created_at) ||
      !cJSON_IsNumber(kind) || !cJSON_IsArray(tags) || !cJSON_IsString(content))
    return NULL;

  arr = cJSON_CreateArray();
  if (arr == NULL) return NULL;
  cJSON_AddItemToArray(arr, cJSON_CreateNumber(0));
  cJSON_AddItemToArray(arr, cJSON_CreateString(pubkey->valuestring));
  cJSON_AddItemToArray(arr, cJSON_CreateNumber(created_at->valuedouble));
  cJSON_AddItemToArray(arr, cJSON_CreateNumber(kind->valuedouble));
  cJSON_AddItemToArray(arr, cJSON_Duplicate((cJSON *)tags, 1));
  cJSON_AddItemToArray(arr, cJSON_CreateString(content->valuestring));
  s = cJSON_PrintUnformatted(arr);
  cJSON_Delete(arr);
  return s;
}

/* The stored form: the seven NIP-01 fields in a fixed order, built from the
 * event rather than echoed from the wire. Reads rebuild the same shape from
 * their columns, so a client sees one serialization either way. */
char *
nostr_event_serialize(const char *id, const char *pubkey, long long created_at,
                      int kind, const char *tags_json, const char *content,
                      const char *sig) {
  cJSON *o = cJSON_CreateObject();
  cJSON *tags;
  char *s;

  if (o == NULL) return NULL;
  tags = cJSON_Parse(tags_json != NULL ? tags_json : "[]");
  if (tags == NULL || !cJSON_IsArray(tags)) {
    cJSON_Delete(tags);
    tags = cJSON_CreateArray();
  }
  cJSON_AddStringToObject(o, "id", id);
  cJSON_AddStringToObject(o, "pubkey", pubkey);
  cJSON_AddNumberToObject(o, "created_at", (double)created_at);
  cJSON_AddNumberToObject(o, "kind", kind);
  cJSON_AddItemToObject(o, "tags", tags);
  cJSON_AddStringToObject(o, "content", content != NULL ? content : "");
  cJSON_AddStringToObject(o, "sig", sig);
  s = cJSON_PrintUnformatted(o);
  cJSON_Delete(o);
  return s;
}

char *
nostr_event_json(const cJSON *ev) {
  const cJSON *id = field(ev, "id"), *pubkey = field(ev, "pubkey");
  const cJSON *created_at = field(ev, "created_at"), *kind = field(ev, "kind");
  const cJSON *tags = field(ev, "tags"), *content = field(ev, "content");
  const cJSON *sig = field(ev, "sig");
  char *tags_json, *out;

  if (!cJSON_IsString(id) || !cJSON_IsString(pubkey) ||
      !cJSON_IsNumber(created_at) || !cJSON_IsNumber(kind) ||
      !cJSON_IsString(content) || !cJSON_IsString(sig))
    return NULL;
  tags_json = cJSON_PrintUnformatted((cJSON *)tags);
  out = nostr_event_serialize(id->valuestring, pubkey->valuestring,
                              (long long)created_at->valuedouble,
                              (int)kind->valuedouble, tags_json,
                              content->valuestring, sig->valuestring);
  free(tags_json);
  return out;
}

bool
nostr_event_id(const cJSON *ev, char *id_hex) {
  char *s = nostr_event_canonical(ev);
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int n = 0;
  int i, ok;

  if (s == NULL) return false;
  ok = EVP_Digest(s, strlen(s), md, &n, EVP_sha256(), NULL);
  free(s);
  if (!ok || n != 32) return false;
  for (i = 0; i < 32; i++) sprintf(id_hex + i * 2, "%02x", md[i]);
  return true;
}

/* NIP-26: does `conditions` allow this event?  Conditions are joined with
 * "&"; several kind= conditions are alternatives, while the created_at
 * bounds all have to hold. An unrecognised condition rejects the token
 * rather than being ignored, so a narrower delegation is never widened. */
static bool
delegation_conditions_ok(const char *conditions, long long kind,
                         long long created_at) {
  const char *p = conditions;
  bool kind_seen = false, kind_ok = false;

  if (*p == '\0') return false;
  while (*p != '\0') {
    const char *end = strchr(p, '&');
    size_t n = end != NULL ? (size_t)(end - p) : strlen(p);
    char buf[64];
    if (n == 0 || n >= sizeof buf) return false;
    memcpy(buf, p, n);
    buf[n] = '\0';
    if (strncmp(buf, "kind=", 5) == 0) {
      kind_seen = true;
      if (atoll(buf + 5) == kind) kind_ok = true;
    } else if (strncmp(buf, "created_at<", 11) == 0) {
      if (created_at >= atoll(buf + 11)) return false;
    } else if (strncmp(buf, "created_at>", 11) == 0) {
      if (created_at <= atoll(buf + 11)) return false;
    } else {
      return false;
    }
    p = end != NULL ? end + 1 : p + n;
  }
  return !kind_seen || kind_ok;
}

/* NIP-26: a ["delegation", <delegator>, <conditions>, <sig>] tag says the
 * delegator authorised this event's pubkey to sign on its behalf. The
 * delegator signs sha256("nostr:delegation:<pubkey>:<conditions>"). A tag
 * that is present but does not verify makes the whole event invalid. */
static const char *
check_delegation(const cJSON *ev) {
  const cJSON *tags = field(ev, "tags"), *t;
  const cJSON *kind = field(ev, "kind"), *created_at = field(ev, "created_at");
  const cJSON *pubkey = field(ev, "pubkey");

  for (t = cJSON_IsArray(tags) ? tags->child : NULL; t != NULL; t = t->next) {
    const cJSON *tn, *dele, *cond, *dsig;
    char token[256];
    unsigned char md[EVP_MAX_MD_SIZE], pk[32], sg[64];
    unsigned int mdlen = 0;
    secp256k1_xonly_pubkey xpk;
    int n;

    if (!cJSON_IsArray(t) || cJSON_GetArraySize((cJSON *)t) < 4) continue;
    tn = t->child;
    if (!cJSON_IsString(tn) || strcmp(tn->valuestring, "delegation") != 0)
      continue;
    dele = tn->next;
    cond = dele != NULL ? dele->next : NULL;
    dsig = cond != NULL ? cond->next : NULL;
    if (!cJSON_IsString(dele) || !cJSON_IsString(cond) || !cJSON_IsString(dsig))
      return "invalid: malformed delegation tag";
    if (!nostr_is_hex(dele->valuestring, 64))
      return "invalid: delegation pubkey must be 64 lowercase hex characters";
    if (!nostr_is_hex(dsig->valuestring, 128))
      return "invalid: delegation sig must be 128 lowercase hex characters";
    if (!delegation_conditions_ok(cond->valuestring,
                                  (long long)kind->valuedouble,
                                  (long long)created_at->valuedouble))
      return "invalid: delegation conditions do not allow this event";

    n = snprintf(token, sizeof token, "nostr:delegation:%s:%s",
                 pubkey->valuestring, cond->valuestring);
    if (n < 0 || (size_t)n >= sizeof token)
      return "invalid: delegation conditions too long";
    if (!EVP_Digest(token, (size_t)n, md, &mdlen, EVP_sha256(), NULL) ||
        mdlen != 32)
      return "invalid: cannot hash delegation token";
    hex2bin(dele->valuestring, pk, sizeof pk);
    hex2bin(dsig->valuestring, sg, sizeof sg);
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &xpk, pk))
      return "invalid: bad delegation pubkey";
    if (!secp256k1_schnorrsig_verify(secp256k1_context_static, sg, md, 32,
                                     &xpk))
      return "invalid: bad delegation signature";
    return NULL; /* first delegation tag wins, like every other tag lookup */
  }
  return NULL;
}

const char *
nostr_event_validate(const cJSON *ev) {
  const cJSON *id, *pubkey, *sig, *created_at, *kind, *tags, *content, *t, *e;
  char id_hex[65];
  unsigned char pk[32], sg[64], msg[32];
  secp256k1_xonly_pubkey xpk;
  double k;

  if (!cJSON_IsObject(ev)) return "invalid: event is not an object";
  if (has_duplicate_member(ev)) return "invalid: duplicate member in event";
  id = field(ev, "id");
  pubkey = field(ev, "pubkey");
  sig = field(ev, "sig");
  created_at = field(ev, "created_at");
  kind = field(ev, "kind");
  tags = field(ev, "tags");
  content = field(ev, "content");

  if (!cJSON_IsString(id) || !nostr_is_hex(id->valuestring, 64))
    return "invalid: id must be 64 lowercase hex characters";
  if (!cJSON_IsString(pubkey) || !nostr_is_hex(pubkey->valuestring, 64))
    return "invalid: pubkey must be 64 lowercase hex characters";
  if (!cJSON_IsString(sig) || !nostr_is_hex(sig->valuestring, 128))
    return "invalid: sig must be 128 lowercase hex characters";
  if (!cJSON_IsNumber(created_at))
    return "invalid: created_at must be a number";
  if (!cJSON_IsNumber(kind))
    return "invalid: kind must be a number";
  k = kind->valuedouble;
  if (k < 0 || k > 65535 || k != (double)(long long)k)
    return "invalid: kind out of range";
  if (!cJSON_IsArray(tags))
    return "invalid: tags must be an array";
  for (t = tags->child; t != NULL; t = t->next) {
    if (!cJSON_IsArray(t)) return "invalid: tag must be an array";
    for (e = t->child; e != NULL; e = e->next)
      if (!cJSON_IsString(e)) return "invalid: tag element must be a string";
  }
  if (!cJSON_IsString(content))
    return "invalid: content must be a string";
  if (created_at->valuedouble > (double)time(NULL) + 900)
    return "invalid: created_at too far in the future";

  if (!nostr_event_id(ev, id_hex))
    return "invalid: cannot serialize event";
  if (strcmp(id_hex, id->valuestring) != 0)
    return "invalid: id does not match";

  hex2bin(pubkey->valuestring, pk, sizeof pk);
  hex2bin(sig->valuestring, sg, sizeof sg);
  hex2bin(id_hex, msg, sizeof msg);
  if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &xpk, pk))
    return "invalid: bad pubkey";
  if (!secp256k1_schnorrsig_verify(secp256k1_context_static, sg, msg, sizeof msg, &xpk))
    return "invalid: bad signature";
  return check_delegation(ev);
}

static bool
contains_string(const cJSON *arr, const char *s) {
  const cJSON *e;
  for (e = arr->child; e != NULL; e = e->next)
    if (cJSON_IsString(e) && strcmp(e->valuestring, s) == 0) return true;
  return false;
}

/* ASCII case-insensitive substring search, matching what sqlite's LIKE does
 * for the stored-query side of NIP-50. */
static bool
contains_fold(const char *hay, const char *needle) {
  size_t nl = strlen(needle), i;
  if (nl == 0) return false;
  for (; *hay != '\0'; hay++) {
    for (i = 0; i < nl; i++) {
      char a = hay[i], b = needle[i];
      if (a == '\0') return false;
      if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
      if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
      if (a != b) break;
    }
    if (i == nl) return true;
  }
  return false;
}

static bool
contains_int(const cJSON *arr, long long v) {
  const cJSON *e;
  for (e = arr->child; e != NULL; e = e->next)
    if (cJSON_IsNumber(e) && (long long)e->valuedouble == v) return true;
  return false;
}

bool
nostr_filter_match(const cJSON *filter, const cJSON *ev) {
  const cJSON *id = field(ev, "id");
  const cJSON *pubkey = field(ev, "pubkey");
  const cJSON *created_at = field(ev, "created_at");
  const cJSON *kind = field(ev, "kind");
  const cJSON *tags = field(ev, "tags");
  const cJSON *f;

  if (!cJSON_IsObject(filter)) return false;
  for (f = filter->child; f != NULL; f = f->next) {
    const char *key = f->string;
    if (key == NULL) continue;
    if (strcmp(key, "ids") == 0) {
      if (!cJSON_IsArray(f) || !cJSON_IsString(id) ||
          !contains_string(f, id->valuestring)) return false;
    } else if (strcmp(key, "authors") == 0) {
      if (!cJSON_IsArray(f) || !cJSON_IsString(pubkey) ||
          !contains_string(f, pubkey->valuestring)) return false;
    } else if (strcmp(key, "kinds") == 0) {
      if (!cJSON_IsArray(f) || !cJSON_IsNumber(kind) ||
          !contains_int(f, (long long)kind->valuedouble)) return false;
    } else if (strcmp(key, "since") == 0) {
      if (!cJSON_IsNumber(f) || !cJSON_IsNumber(created_at) ||
          created_at->valuedouble < f->valuedouble) return false;
    } else if (strcmp(key, "until") == 0) {
      if (!cJSON_IsNumber(f) || !cJSON_IsNumber(created_at) ||
          created_at->valuedouble > f->valuedouble) return false;
    } else if (strcmp(key, "search") == 0) {
      /* NIP-50: the stored query is a substring match over content, so the
       * live path has to agree or the same subscription answers differently
       * before and after EOSE. Case folding is ASCII only, like sqlite LIKE. */
      const cJSON *content = field(ev, "content");
      if (!cJSON_IsString(f) || f->valuestring[0] == '\0' ||
          !cJSON_IsString(content) ||
          !contains_fold(content->valuestring, f->valuestring))
        return false;
    } else if (key[0] == '#' && key[1] != '\0' && key[2] == '\0') {
      const char *name = key + 1;
      const cJSON *t;
      bool found = false;
      if (!cJSON_IsArray(f)) return false;
      for (t = cJSON_IsArray(tags) ? tags->child : NULL;
           t != NULL && !found; t = t->next) {
        const cJSON *tn, *tv;
        if (!cJSON_IsArray(t)) continue;
        tn = t->child;
        if (tn == NULL || !cJSON_IsString(tn) ||
            strcmp(tn->valuestring, name) != 0) continue;
        tv = tn->next;
        if (tv != NULL && cJSON_IsString(tv) &&
            contains_string(f, tv->valuestring)) found = true;
      }
      if (!found) return false;
    }
    /* "limit" and unknown keys are ignored for live matching */
  }
  return true;
}

bool
nostr_filters_match(const cJSON *filters, const cJSON *ev) {
  const cJSON *f;
  if (!cJSON_IsArray(filters)) return false;
  for (f = filters->child; f != NULL; f = f->next)
    if (nostr_filter_match(f, ev)) return true;
  return false;
}

const char *
nostr_tag_value(const cJSON *ev, const char *name) {
  const cJSON *tags = cJSON_GetObjectItemCaseSensitive((cJSON *)ev, "tags");
  const cJSON *t;
  for (t = cJSON_IsArray(tags) ? tags->child : NULL; t != NULL; t = t->next) {
    const cJSON *tn, *tv;
    if (!cJSON_IsArray(t)) continue;
    tn = t->child;
    if (tn == NULL || !cJSON_IsString(tn) || strcmp(tn->valuestring, name) != 0)
      continue;
    tv = tn->next;
    return (tv != NULL && cJSON_IsString(tv)) ? tv->valuestring : "";
  }
  return NULL;
}
