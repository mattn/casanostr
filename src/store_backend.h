#ifndef CASANOSTR_STORE_BACKEND_H
#define CASANOSTR_STORE_BACKEND_H

#include "store.h"

/* One storage backend; store_init() picks one and forwards to it. */
struct store_backend {
  bool (*init)(const char *path);
  void (*close)(void);
  store_result (*event)(const cJSON *ev);
  bool (*query)(const cJSON *filter,
                int (*emit)(const char *id, const char *raw, void *ud),
                void *ud);
  bool (*count)(const cJSON *filter, long long *out);
};

void store_backend_sqlite3(struct store_backend *be);
void store_backend_postgresql(struct store_backend *be);

#endif
