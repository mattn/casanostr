#ifndef CASANOSTR_STORE_H
#define CASANOSTR_STORE_H

#include <stdbool.h>
#include "cJSON.h"

typedef enum {
  STORE_NEW,        /* stored */
  STORE_DUPLICATE,  /* already have it (or replaced by a newer one) */
  STORE_EPHEMERAL,  /* valid but not stored */
  STORE_ERROR
} store_result;

bool store_init(const char *path);
void store_close(void);

/* raw is the compact JSON serialization of ev, stored verbatim. */
store_result store_event(const cJSON *ev, const char *raw);

/* Query stored events matching a single filter, newest first.
 * emit is called outside the internal lock; return nonzero to stop. */
bool store_query(const cJSON *filter,
                 int (*emit)(const char *id, const char *raw, void *ud),
                 void *ud);

/* NIP-45: number of stored events matching a single filter. */
bool store_count(const cJSON *filter, long long *out);

#endif
