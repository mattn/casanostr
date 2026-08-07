#include "store_backend.h"
#include "nostr.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static struct store_backend g_be;

bool
store_init(const char *path) {
  if (strncmp(path, "postgres://", 11) == 0 ||
      strncmp(path, "postgresql://", 13) == 0)
    store_backend_postgresql(&g_be);
  else
    store_backend_sqlite3(&g_be);
  return g_be.init(path);
}

void
store_close(void) {
  if (g_be.close != NULL) g_be.close();
}

store_result
store_event(const cJSON *ev, const char *raw) {
  return g_be.event(ev, raw);
}

struct emit_ctx {
  int (*emit)(const char *id, const char *raw, void *ud);
  void *ud;
};

/* NIP-40: expired events stay in the database but are dropped at delivery
 * time, backend-independently.  COUNT keeps counting them. */
static int
emit_unexpired(const char *id, const char *raw, void *ud) {
  struct emit_ctx *ctx = ud;
  cJSON *ev = cJSON_Parse(raw);
  bool expired = false;
  if (ev != NULL) {
    const char *exp = nostr_tag_value(ev, "expiration");
    if (exp != NULL) {
      long long e = atoll(exp);
      expired = e > 0 && e <= (long long)time(NULL);
    }
    cJSON_Delete(ev);
  }
  if (expired) return 0;
  return ctx->emit(id, raw, ctx->ud);
}

bool
store_query(const cJSON *filter,
            int (*emit)(const char *id, const char *raw, void *ud), void *ud) {
  struct emit_ctx ctx = {emit, ud};
  return g_be.query(filter, emit_unexpired, &ctx);
}

bool
store_count(const cJSON *filter, long long *out) {
  return g_be.count(filter, out);
}
