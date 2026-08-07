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
  return NULL;
}

static bool
contains_string(const cJSON *arr, const char *s) {
  const cJSON *e;
  for (e = arr->child; e != NULL; e = e->next)
    if (cJSON_IsString(e) && strcmp(e->valuestring, s) == 0) return true;
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
