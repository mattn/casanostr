#include "store_backend.h"
#include "nostr.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sqlite3 *g_db;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *schema =
    "CREATE TABLE IF NOT EXISTS event ("
    "  id TEXT PRIMARY KEY,"
    "  pubkey TEXT NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  kind INTEGER NOT NULL,"
    "  raw TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS tag ("
    "  event_id TEXT NOT NULL,"
    "  name TEXT NOT NULL,"
    "  value TEXT NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_event_created ON event(created_at DESC);"
    "CREATE INDEX IF NOT EXISTS idx_event_kind_pubkey ON event(kind, pubkey);"
    "CREATE INDEX IF NOT EXISTS idx_event_pubkey ON event(pubkey);"
    "CREATE INDEX IF NOT EXISTS idx_tag_event ON tag(event_id);"
    "CREATE INDEX IF NOT EXISTS idx_tag_name_value ON tag(name, value);"
    "CREATE TRIGGER IF NOT EXISTS tr_event_delete AFTER DELETE ON event BEGIN"
    "  DELETE FROM tag WHERE event_id = OLD.id;"
    "END;";

static bool
db_init(const char *path) {
  char *err = NULL;
  if (sqlite3_open_v2(path, &g_db,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                          SQLITE_OPEN_FULLMUTEX,
                      NULL) != SQLITE_OK) {
    fprintf(stderr, "sqlite3: %s\n", sqlite3_errmsg(g_db));
    return false;
  }
  sqlite3_exec(g_db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;",
               NULL, NULL, NULL);
  if (sqlite3_exec(g_db, schema, NULL, NULL, &err) != SQLITE_OK) {
    fprintf(stderr, "sqlite3: %s\n", err);
    sqlite3_free(err);
    return false;
  }
  return true;
}

static void
db_close(void) {
  if (g_db != NULL) sqlite3_close(g_db);
  g_db = NULL;
}

/* NIP-50: wrap a search string as a LIKE pattern, escaping the wildcards so
 * a search for "100%" cannot match everything. Caller frees. */
static char *
like_pattern(const char *s) {
  size_t n = strlen(s), i, j = 0;
  char *out;
  if (n > 4096) return NULL; /* a search term this long is not a search */
  out = malloc(n * 2 + 3);
  if (out == NULL) return NULL;
  out[j++] = '%';
  for (i = 0; i < n; i++) {
    if (s[i] == '%' || s[i] == '_' || s[i] == '\\') out[j++] = '\\';
    out[j++] = s[i];
  }
  out[j++] = '%';
  out[j] = '\0';
  return out;
}

static bool
execf(const char *fmt, ...) {
  va_list ap;
  char *sql, *err = NULL;
  int rc;

  va_start(ap, fmt);
  sql = sqlite3_vmprintf(fmt, ap);
  va_end(ap);
  if (sql == NULL) return false;
  rc = sqlite3_exec(g_db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "sqlite3: %s: %s\n", err != NULL ? err : "error", sql);
    sqlite3_free(err);
  }
  sqlite3_free(sql);
  return rc == SQLITE_OK;
}

static const cJSON *
field(const cJSON *ev, const char *name) {
  return cJSON_GetObjectItemCaseSensitive((cJSON *)ev, name);
}

/* first value of the first tag named `name`, or NULL */
static const char *
tag_value(const cJSON *ev, const char *name) {
  const cJSON *tags = field(ev, "tags"), *t;
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

/* Is there a stored (pubkey, kind [, d-tag]) event that should win over
 * the incoming one?  Ties on created_at go to the lower id. */
static bool
newer_exists(const char *pubkey, int kind, const char *d,
             long long created_at, const char *id) {
  char *sql;
  sqlite3_stmt *st = NULL;
  bool newer = false;

  if (d != NULL)
    sql = sqlite3_mprintf(
        "SELECT created_at, id FROM event WHERE pubkey=%Q AND kind=%d"
        " AND id IN (SELECT event_id FROM tag WHERE name='d' AND value=%Q)"
        " ORDER BY created_at DESC, id ASC LIMIT 1", pubkey, kind, d);
  else
    sql = sqlite3_mprintf(
        "SELECT created_at, id FROM event WHERE pubkey=%Q AND kind=%d"
        " ORDER BY created_at DESC, id ASC LIMIT 1", pubkey, kind);
  if (sql == NULL) return false;
  if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) == SQLITE_OK) {
    if (sqlite3_step(st) == SQLITE_ROW) {
      long long ca = sqlite3_column_int64(st, 0);
      const char *eid = (const char *)sqlite3_column_text(st, 1);
      if (ca > created_at ||
          (ca == created_at && eid != NULL && strcmp(eid, id) <= 0))
        newer = true;
    }
  }
  sqlite3_finalize(st);
  sqlite3_free(sql);
  return newer;
}

/* NIP-09: delete this pubkey's events referenced by "e" tags */
static bool
apply_deletion(const cJSON *ev, const char *pubkey) {
  const cJSON *tags = field(ev, "tags"), *t;
  for (t = cJSON_IsArray(tags) ? tags->child : NULL; t != NULL; t = t->next) {
    const cJSON *tn, *tv;
    if (!cJSON_IsArray(t)) continue;
    tn = t->child;
    if (tn == NULL || !cJSON_IsString(tn) || strcmp(tn->valuestring, "e") != 0)
      continue;
    tv = tn->next;
    if (tv == NULL || !cJSON_IsString(tv) || !nostr_is_hex(tv->valuestring, 64))
      continue;
    if (!execf("DELETE FROM event WHERE id=%Q AND pubkey=%Q AND kind<>5",
               tv->valuestring, pubkey))
      return false;
  }
  return true;
}

static bool
insert_tags(const cJSON *ev, const char *id, bool addressable) {
  const cJSON *tags = field(ev, "tags"), *t;
  bool has_d = false;
  for (t = cJSON_IsArray(tags) ? tags->child : NULL; t != NULL; t = t->next) {
    const cJSON *tn, *tv;
    if (!cJSON_IsArray(t)) continue;
    tn = t->child;
    if (tn == NULL || !cJSON_IsString(tn) || strlen(tn->valuestring) != 1)
      continue;  /* only single-letter tags are indexed (NIP-01) */
    tv = tn->next;
    if (!execf("INSERT INTO tag (event_id, name, value) VALUES (%Q, %Q, %Q)",
               id, tn->valuestring,
               (tv != NULL && cJSON_IsString(tv)) ? tv->valuestring : ""))
      return false;
    if (tn->valuestring[0] == 'd') has_d = true;
  }
  /* synthesize d="" so addressable events without a d tag are replaceable */
  if (addressable && !has_d)
    return execf("INSERT INTO tag (event_id, name, value) VALUES (%Q, 'd', '')",
                 id);
  return true;
}

static store_result
db_event(const cJSON *ev, const char *raw) {
  const cJSON *jid = field(ev, "id"), *jpk = field(ev, "pubkey");
  const cJSON *jca = field(ev, "created_at"), *jk = field(ev, "kind");
  const char *id, *pubkey;
  long long created_at;
  int kind;
  bool addressable = false;
  store_result res = STORE_NEW;

  if (!cJSON_IsString(jid) || !cJSON_IsString(jpk) || !cJSON_IsNumber(jca) ||
      !cJSON_IsNumber(jk))
    return STORE_ERROR;
  id = jid->valuestring;
  pubkey = jpk->valuestring;
  created_at = (long long)jca->valuedouble;
  kind = (int)jk->valuedouble;

  if (kind >= 20000 && kind < 30000) return STORE_EPHEMERAL;

  pthread_mutex_lock(&g_mutex);
  if (!execf("BEGIN IMMEDIATE")) {
    pthread_mutex_unlock(&g_mutex);
    return STORE_ERROR;
  }

  if (kind == 0 || kind == 3 || (kind >= 10000 && kind < 20000)) {
    if (newer_exists(pubkey, kind, NULL, created_at, id))
      res = STORE_DUPLICATE;
    else
      execf("DELETE FROM event WHERE pubkey=%Q AND kind=%d", pubkey, kind);
  } else if (kind >= 30000 && kind < 40000) {
    const char *d = tag_value(ev, "d");
    addressable = true;
    if (d == NULL) d = "";
    if (newer_exists(pubkey, kind, d, created_at, id))
      res = STORE_DUPLICATE;
    else
      execf("DELETE FROM event WHERE pubkey=%Q AND kind=%d AND id IN"
            " (SELECT event_id FROM tag WHERE name='d' AND value=%Q)",
            pubkey, kind, d);
  }

  if (res == STORE_NEW) {
    if (!execf("INSERT OR IGNORE INTO event (id, pubkey, created_at, kind, raw)"
               " VALUES (%Q, %Q, %lld, %d, %Q)",
               id, pubkey, created_at, kind, raw)) {
      res = STORE_ERROR;
    } else if (sqlite3_changes(g_db) == 0) {
      res = STORE_DUPLICATE;
    } else if (!insert_tags(ev, id, addressable) ||
               (kind == 5 && !apply_deletion(ev, pubkey))) {
      /* an event stored without its tags is unfindable by tag filters, so
       * roll the whole thing back rather than report it as stored */
      res = STORE_ERROR;
    }
  }

  /* replaceable and addressable events prune the older rows before the
   * insert, so committing a failed insert would drop the stored event
   * without putting the new one in its place */
  execf(res == STORE_ERROR ? "ROLLBACK" : "COMMIT");
  pthread_mutex_unlock(&g_mutex);
  return res;
}

struct row {
  char *id;
  char *raw;
};

/* Append the filter's conditions to a query of the event table.  Sets
 * *none when the filter can match nothing and *limit when the filter
 * carries one. */
static void
build_where(sqlite3_str *s, const cJSON *filter, int *limit, bool *none) {
  const cJSON *f;
  for (f = filter->child; f != NULL; f = f->next) {
    const char *key = f->string;
    const cJSON *e;
    int n = 0;
    if (key == NULL) continue;
    if (strcmp(key, "ids") == 0 || strcmp(key, "authors") == 0) {
      if (!cJSON_IsArray(f)) { *none = true; continue; }
      sqlite3_str_appendf(s, " AND %s IN (", key[0] == 'i' ? "id" : "pubkey");
      for (e = f->child; e != NULL; e = e->next)
        if (cJSON_IsString(e))
          sqlite3_str_appendf(s, "%s%Q", n++ ? "," : "", e->valuestring);
      sqlite3_str_appendall(s, ")");
      if (n == 0) *none = true;
    } else if (strcmp(key, "kinds") == 0) {
      if (!cJSON_IsArray(f)) { *none = true; continue; }
      sqlite3_str_appendall(s, " AND kind IN (");
      for (e = f->child; e != NULL; e = e->next)
        if (cJSON_IsNumber(e))
          sqlite3_str_appendf(s, "%s%d", n++ ? "," : "",
                              (int)e->valuedouble);
      sqlite3_str_appendall(s, ")");
      if (n == 0) *none = true;
    } else if (strcmp(key, "since") == 0 && cJSON_IsNumber(f)) {
      sqlite3_str_appendf(s, " AND created_at >= %lld",
                          (long long)f->valuedouble);
    } else if (strcmp(key, "until") == 0 && cJSON_IsNumber(f)) {
      sqlite3_str_appendf(s, " AND created_at <= %lld",
                          (long long)f->valuedouble);
    } else if (strcmp(key, "search") == 0) {
      /* NIP-50: substring match over content. sqlite's LIKE folds case for
       * ASCII only, which is as far as this backend goes. */
      char *pat;
      if (!cJSON_IsString(f) || f->valuestring[0] == '\0') {
        *none = true;
        continue;
      }
      pat = like_pattern(f->valuestring);
      if (pat == NULL) {
        *none = true;
        continue;
      }
      /* the event is stored whole in `raw`, so pull content back out rather
       * than matching the serialized form and hitting ids and tags too */
      sqlite3_str_appendf(s,
                          " AND json_extract(raw, '$.content') LIKE %Q"
                          " ESCAPE '\\'",
                          pat);
      free(pat);
    } else if (strcmp(key, "limit") == 0 && cJSON_IsNumber(f)) {
      double v = f->valuedouble;
      if (v >= 0) {
        /* clamp before the cast so a huge double stays in range; a limit of
         * zero asks for no stored events and is not an unset limit */
        *limit = v > 1000 ? 1000 : (int)v;
        if (*limit == 0) *none = true;
      }
    } else if (key[0] == '#' && key[1] != '\0' && key[2] == '\0') {
      if (!cJSON_IsArray(f)) { *none = true; continue; }
      sqlite3_str_appendf(s, " AND EXISTS (SELECT 1 FROM tag WHERE"
                             " tag.event_id = event.id AND tag.name = %Q"
                             " AND tag.value IN (", key + 1);
      for (e = f->child; e != NULL; e = e->next)
        if (cJSON_IsString(e))
          sqlite3_str_appendf(s, "%s%Q", n++ ? "," : "", e->valuestring);
      sqlite3_str_appendall(s, "))");
      if (n == 0) *none = true;
    }
  }
}

static bool
db_query(const cJSON *filter,
         int (*emit)(const char *id, const char *raw, void *ud), void *ud) {
  sqlite3_str *s;
  sqlite3_stmt *st = NULL;
  char *sql;
  int limit = 500, i, nrows = 0, cap = 0;
  bool none = false, ok = true;
  struct row *rows = NULL;

  if (!cJSON_IsObject(filter)) return false;

  pthread_mutex_lock(&g_mutex);
  s = sqlite3_str_new(g_db);
  sqlite3_str_appendall(s, "SELECT id, raw FROM event WHERE 1");
  build_where(s, filter, &limit, &none);
  sqlite3_str_appendf(s, " ORDER BY created_at DESC, id ASC LIMIT %d", limit);
  sql = sqlite3_str_finish(s);

  if (sql == NULL) {
    ok = false;
  } else if (!none) {
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) {
      fprintf(stderr, "sqlite3: %s: %s\n", sqlite3_errmsg(g_db), sql);
      ok = false;
    } else {
      while (sqlite3_step(st) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        const char *raw = (const char *)sqlite3_column_text(st, 1);
        if (id == NULL || raw == NULL) continue;
        if (nrows == cap) {
          int ncap = cap ? cap * 2 : 64;
          struct row *nr = realloc(rows, sizeof(struct row) * ncap);
          if (nr == NULL) { ok = false; break; }
          rows = nr;
          cap = ncap;
        }
        rows[nrows].id = strdup(id);
        rows[nrows].raw = strdup(raw);
        if (rows[nrows].id == NULL || rows[nrows].raw == NULL) {
          free(rows[nrows].id);
          free(rows[nrows].raw);
          ok = false;
          break;
        }
        nrows++;
      }
      sqlite3_finalize(st);
    }
  }
  sqlite3_free(sql);
  pthread_mutex_unlock(&g_mutex);

  /* emit outside the lock so slow clients cannot stall the store */
  for (i = 0; i < nrows; i++) {
    if (ok && emit(rows[i].id, rows[i].raw, ud) != 0) ok = false;
    free(rows[i].id);
    free(rows[i].raw);
  }
  free(rows);
  return ok;
}

static bool
db_count(const cJSON *filter, long long *out) {
  sqlite3_str *s;
  sqlite3_stmt *st = NULL;
  char *sql;
  int limit = 500;
  bool none = false, ok = true;

  *out = 0;
  if (!cJSON_IsObject(filter)) return false;

  pthread_mutex_lock(&g_mutex);
  s = sqlite3_str_new(g_db);
  sqlite3_str_appendall(s, "SELECT count(*) FROM event WHERE 1");
  build_where(s, filter, &limit, &none);
  sql = sqlite3_str_finish(s);

  if (sql == NULL) {
    ok = false;
  } else if (!none) {
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) {
      fprintf(stderr, "sqlite3: %s: %s\n", sqlite3_errmsg(g_db), sql);
      ok = false;
    } else {
      if (sqlite3_step(st) == SQLITE_ROW) *out = sqlite3_column_int64(st, 0);
      sqlite3_finalize(st);
    }
  }
  sqlite3_free(sql);
  pthread_mutex_unlock(&g_mutex);
  return ok;
}

void
store_backend_sqlite3(struct store_backend *be) {
  be->init = db_init;
  be->close = db_close;
  be->event = db_event;
  be->query = db_query;
  be->count = db_count;
}
