#include "store_backend.h"

#include <string.h>

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

bool
store_query(const cJSON *filter,
            int (*emit)(const char *id, const char *raw, void *ud), void *ud) {
  return g_be.query(filter, emit, ud);
}
