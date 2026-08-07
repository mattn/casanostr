/* gen_event: generate a signed nostr event for testing.
 *
 *   gen_event [-s seckey_hex] [-k kind] [-c content] [-t name[=value]]...
 *             [-T created_at] [-d delegator_seckey_hex] [-C conditions]
 *
 * Prints the event as compact JSON on stdout. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include "cJSON.h"
#include "nostr.h"

static void
die(const char *msg) {
  fprintf(stderr, "gen_event: %s\n", msg);
  exit(1);
}

static bool
hex2bin(const char *s, unsigned char *out, size_t outlen) {
  size_t i;
  if (strlen(s) != outlen * 2) return false;
  for (i = 0; i < outlen; i++)
    if (sscanf(s + i * 2, "%2hhx", &out[i]) != 1) return false;
  return true;
}

static void
bin2hex(const unsigned char *in, size_t inlen, char *out) {
  size_t i;
  for (i = 0; i < inlen; i++) sprintf(out + i * 2, "%02x", in[i]);
}

static void
urandom(unsigned char *buf, size_t n) {
  FILE *f = fopen("/dev/urandom", "rb");
  if (f == NULL || fread(buf, 1, n, f) != n) die("cannot read /dev/urandom");
  fclose(f);
}

int
main(int argc, char **argv) {
  const char *seckey_hex = NULL, *content = "hello";
  const char *delegator_hex = NULL, *conditions = "";
  int opt, kind = 1;
  long long created_at = 0;
  cJSON *tags = cJSON_CreateArray(), *ev;
  unsigned char sk[32], pk[32], id32[32], sig[64], aux[32];
  char pk_hex[65], id_hex[65], sig_hex[129], *out;
  secp256k1_context *ctx;
  secp256k1_keypair kp;
  secp256k1_xonly_pubkey xpk;

  while ((opt = getopt(argc, argv, "s:k:c:t:T:d:C:h")) != -1) {
    switch (opt) {
    case 's':
      seckey_hex = optarg;
      break;
    case 'k':
      kind = atoi(optarg);
      break;
    case 'c':
      content = optarg;
      break;
    case 'T':
      created_at = atoll(optarg);
      break;
    case 'd':
      delegator_hex = optarg;
      break;
    case 'C':
      conditions = optarg;
      break;
    case 't': {
      /* name=value, or a bare name for a single-element tag such as ["-"] */
      char *eq = strchr(optarg, '=');
      cJSON *tag = cJSON_CreateArray();
      if (eq != NULL) *eq = '\0';
      cJSON_AddItemToArray(tag, cJSON_CreateString(optarg));
      if (eq != NULL) cJSON_AddItemToArray(tag, cJSON_CreateString(eq + 1));
      cJSON_AddItemToArray(tags, tag);
      break;
    }
    default:
      fprintf(stderr, "usage: gen_event [-s seckey_hex] [-k kind]"
                      " [-c content] [-t name=value]... [-T created_at]\n");
      return opt == 'h' ? 0 : 1;
    }
  }

  if (seckey_hex != NULL) {
    if (!hex2bin(seckey_hex, sk, sizeof sk)) die("bad -s seckey");
  } else {
    urandom(sk, sizeof sk);
  }
  if (created_at == 0) created_at = (long long)time(NULL);

  ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  if (!secp256k1_keypair_create(ctx, &kp, sk)) die("bad secret key");
  if (!secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp)) die("keypair");
  secp256k1_xonly_pubkey_serialize(ctx, pk, &xpk);
  bin2hex(pk, sizeof pk, pk_hex);

  /* NIP-26: sign nostr:delegation:<pubkey>:<conditions> with the delegator
   * key and attach the result, so the event is signed by this key but
   * authorised by the delegator. */
  if (delegator_hex != NULL) {
    unsigned char dsk[32], dpk[32], token_hash[32], dsig[64];
    char dpk_hex[65], dsig_hex[129], token[256];
    secp256k1_keypair dkp;
    secp256k1_xonly_pubkey dxpk;
    cJSON *tag;
    unsigned int mdlen = 0;
    int n;

    if (!hex2bin(delegator_hex, dsk, sizeof dsk)) die("bad --delegator");
    if (!secp256k1_keypair_create(ctx, &dkp, dsk)) die("bad delegator key");
    if (!secp256k1_keypair_xonly_pub(ctx, &dxpk, NULL, &dkp)) die("keypair");
    secp256k1_xonly_pubkey_serialize(ctx, dpk, &dxpk);
    bin2hex(dpk, sizeof dpk, dpk_hex);

    n = snprintf(token, sizeof token, "nostr:delegation:%s:%s", pk_hex,
                 conditions);
    if (n < 0 || (size_t)n >= sizeof token) die("conditions too long");
    if (!EVP_Digest(token, (size_t)n, token_hash, &mdlen, EVP_sha256(),
                    NULL) ||
        mdlen != 32)
      die("cannot hash delegation token");
    urandom(aux, sizeof aux);
    if (!secp256k1_schnorrsig_sign32(ctx, dsig, token_hash, &dkp, aux))
      die("sign delegation");
    bin2hex(dsig, sizeof dsig, dsig_hex);

    tag = cJSON_CreateArray();
    cJSON_AddItemToArray(tag, cJSON_CreateString("delegation"));
    cJSON_AddItemToArray(tag, cJSON_CreateString(dpk_hex));
    cJSON_AddItemToArray(tag, cJSON_CreateString(conditions));
    cJSON_AddItemToArray(tag, cJSON_CreateString(dsig_hex));
    cJSON_AddItemToArray(tags, tag);
  }

  ev = cJSON_CreateObject();
  cJSON_AddStringToObject(ev, "pubkey", pk_hex);
  cJSON_AddNumberToObject(ev, "created_at", (double)created_at);
  cJSON_AddNumberToObject(ev, "kind", kind);
  cJSON_AddItemToObject(ev, "tags", tags);
  cJSON_AddStringToObject(ev, "content", content);

  if (!nostr_event_id(ev, id_hex)) die("cannot serialize event");
  hex2bin(id_hex, id32, sizeof id32);
  urandom(aux, sizeof aux);
  if (!secp256k1_schnorrsig_sign32(ctx, sig, id32, &kp, aux)) die("sign");
  bin2hex(sig, sizeof sig, sig_hex);

  cJSON_AddStringToObject(ev, "id", id_hex);
  cJSON_AddStringToObject(ev, "sig", sig_hex);
  out = cJSON_PrintUnformatted(ev);
  puts(out);
  free(out);
  cJSON_Delete(ev);
  secp256k1_context_destroy(ctx);
  return 0;
}
