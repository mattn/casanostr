#include "store_backend.h"
#include "nostr.h"

#include <libpq-fe.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static PGconn *g_conn;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

/* tag rows are removed via ON DELETE CASCADE (sqlite uses a trigger) */
static const char *schema =
    "CREATE TABLE IF NOT EXISTS event ("
    "  id TEXT PRIMARY KEY,"
    "  pubkey TEXT NOT NULL,"
    "  created_at BIGINT NOT NULL,"
    "  kind INTEGER NOT NULL,"
    "  raw TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS tag ("
    "  event_id TEXT NOT NULL REFERENCES event(id) ON DELETE CASCADE,"
    "  name TEXT NOT NULL,"
    "  value TEXT NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_event_created ON event(created_at DESC);"
    "CREATE INDEX IF NOT EXISTS idx_event_kind_pubkey ON event(kind, pubkey);"
    "CREATE INDEX IF NOT EXISTS idx_event_pubkey ON event(pubkey);"
    "CREATE INDEX IF NOT EXISTS idx_tag_event ON tag(event_id);"
    "CREATE INDEX IF NOT EXISTS idx_tag_name_value ON tag(name, value);";

/* run a parameterized statement; NULL on error (caller must PQclear) */
static PGresult *
run(const char *sql, int n, const char **vals) {
  PGresult *r = PQexecParams(g_conn, sql, n, NULL, vals, NULL, NULL, 0);
  ExecStatusType st = PQresultStatus(r);
  if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
    fprintf(stderr, "postgres: %s", PQerrorMessage(g_conn));
    PQclear(r);
    return NULL;
  }
  return r;
}

static bool
exec(const char *sql, int n, const char **vals) {
  PGresult *r = run(sql, n, vals);
  if (r == NULL) return false;
  PQclear(r);
  return true;
}

static bool
db_init(const char *conninfo) {
  PGresult *r;
  g_conn = PQconnectdb(conninfo);
  if (PQstatus(g_conn) != CONNECTION_OK) {
    fprintf(stderr, "postgres: %s", PQerrorMessage(g_conn));
    return false;
  }
  r = PQexec(g_conn, schema);
  if (PQresultStatus(r) != PGRES_COMMAND_OK) {
    fprintf(stderr, "postgres: %s", PQerrorMessage(g_conn));
    PQclear(r);
    return false;
  }
  PQclear(r);
  return true;
}

static void
db_close(void) {
  if (g_conn != NULL) PQfinish(g_conn);
  g_conn = NULL;
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
  char kbuf[16];
  const char *vals[3];
  PGresult *r;
  bool newer = false;

  snprintf(kbuf, sizeof kbuf, "%d", kind);
  vals[0] = pubkey;
  vals[1] = kbuf;
  vals[2] = d;
  if (d != NULL)
    r = run("SELECT created_at, id FROM event WHERE pubkey=$1 AND kind=$2"
            " AND id IN (SELECT event_id FROM tag WHERE name='d' AND value=$3)"
            " ORDER BY created_at DESC, id ASC LIMIT 1", 3, vals);
  else
    r = run("SELECT created_at, id FROM event WHERE pubkey=$1 AND kind=$2"
            " ORDER BY created_at DESC, id ASC LIMIT 1", 2, vals);
  if (r == NULL) return false;
  if (PQntuples(r) > 0) {
    long long ca = atoll(PQgetvalue(r, 0, 0));
    const char *eid = PQgetvalue(r, 0, 1);
    if (ca > created_at ||
        (ca == created_at && strcmp(eid, id) <= 0))
      newer = true;
  }
  PQclear(r);
  return newer;
}

/* NIP-09: delete this pubkey's events referenced by "e" tags */
static void
apply_deletion(const cJSON *ev, const char *pubkey) {
  const cJSON *tags = field(ev, "tags"), *t;
  for (t = cJSON_IsArray(tags) ? tags->child : NULL; t != NULL; t = t->next) {
    const cJSON *tn, *tv;
    const char *vals[2];
    if (!cJSON_IsArray(t)) continue;
    tn = t->child;
    if (tn == NULL || !cJSON_IsString(tn) || strcmp(tn->valuestring, "e") != 0)
      continue;
    tv = tn->next;
    if (tv == NULL || !cJSON_IsString(tv) || !nostr_is_hex(tv->valuestring, 64))
      continue;
    vals[0] = tv->valuestring;
    vals[1] = pubkey;
    exec("DELETE FROM event WHERE id=$1 AND pubkey=$2 AND kind<>5", 2, vals);
  }
}

static void
insert_tags(const cJSON *ev, const char *id, bool addressable) {
  const cJSON *tags = field(ev, "tags"), *t;
  bool has_d = false;
  for (t = cJSON_IsArray(tags) ? tags->child : NULL; t != NULL; t = t->next) {
    const cJSON *tn, *tv;
    const char *vals[3];
    if (!cJSON_IsArray(t)) continue;
    tn = t->child;
    if (tn == NULL || !cJSON_IsString(tn) || strlen(tn->valuestring) != 1)
      continue;  /* only single-letter tags are indexed (NIP-01) */
    tv = tn->next;
    vals[0] = id;
    vals[1] = tn->valuestring;
    vals[2] = (tv != NULL && cJSON_IsString(tv)) ? tv->valuestring : "";
    exec("INSERT INTO tag (event_id, name, value) VALUES ($1, $2, $3)",
         3, vals);
    if (tn->valuestring[0] == 'd') has_d = true;
  }
  /* synthesize d="" so addressable events without a d tag are replaceable */
  if (addressable && !has_d) {
    const char *vals[1] = {id};
    exec("INSERT INTO tag (event_id, name, value) VALUES ($1, 'd', '')",
         1, vals);
  }
}

static store_result
db_event(const cJSON *ev, const char *raw) {
  const cJSON *jid = field(ev, "id"), *jpk = field(ev, "pubkey");
  const cJSON *jca = field(ev, "created_at"), *jk = field(ev, "kind");
  const char *id, *pubkey;
  char kbuf[16], cbuf[32];
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
  snprintf(kbuf, sizeof kbuf, "%d", kind);
  snprintf(cbuf, sizeof cbuf, "%lld", created_at);

  if (kind >= 20000 && kind < 30000) return STORE_EPHEMERAL;

  pthread_mutex_lock(&g_mutex);
  if (!exec("BEGIN", 0, NULL)) {
    pthread_mutex_unlock(&g_mutex);
    return STORE_ERROR;
  }

  if (kind == 0 || kind == 3 || (kind >= 10000 && kind < 20000)) {
    if (newer_exists(pubkey, kind, NULL, created_at, id)) {
      res = STORE_DUPLICATE;
    } else {
      const char *vals[2] = {pubkey, kbuf};
      exec("DELETE FROM event WHERE pubkey=$1 AND kind=$2", 2, vals);
    }
  } else if (kind >= 30000 && kind < 40000) {
    const char *d = tag_value(ev, "d");
    addressable = true;
    if (d == NULL) d = "";
    if (newer_exists(pubkey, kind, d, created_at, id)) {
      res = STORE_DUPLICATE;
    } else {
      const char *vals[3] = {pubkey, kbuf, d};
      exec("DELETE FROM event WHERE pubkey=$1 AND kind=$2 AND id IN"
           " (SELECT event_id FROM tag WHERE name='d' AND value=$3)",
           3, vals);
    }
  }

  if (res == STORE_NEW) {
    const char *vals[5] = {id, pubkey, cbuf, kbuf, raw};
    PGresult *r = run("INSERT INTO event (id, pubkey, created_at, kind, raw)"
                      " VALUES ($1, $2, $3, $4, $5)"
                      " ON CONFLICT (id) DO NOTHING", 5, vals);
    if (r == NULL) {
      res = STORE_ERROR;
    } else {
      bool inserted = strcmp(PQcmdTuples(r), "0") != 0;
      PQclear(r);
      if (!inserted) {
        res = STORE_DUPLICATE;
      } else {
        insert_tags(ev, id, addressable);
        if (kind == 5) apply_deletion(ev, pubkey);
      }
    }
  }

  exec(res == STORE_ERROR ? "ROLLBACK" : "COMMIT", 0, NULL);
  pthread_mutex_unlock(&g_mutex);
  return res;
}

/* --- query --------------------------------------------------------------- */

struct buf {
  char *s;
  size_t len, cap;
  bool fail;
};

static void
buf_add(struct buf *b, const char *s) {
  size_t n = strlen(s);
  if (b->fail) return;
  if (b->len + n + 1 > b->cap) {
    size_t cap = b->cap ? b->cap : 256;
    char *p;
    while (b->len + n + 1 > cap) cap *= 2;
    p = realloc(b->s, cap);
    if (p == NULL) {
      b->fail = true;
      return;
    }
    b->s = p;
    b->cap = cap;
  }
  memcpy(b->s + b->len, s, n + 1);
  b->len += n;
}

static void
buf_addf(struct buf *b, const char *fmt, ...) {
  char tmp[64];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(tmp, sizeof tmp, fmt, ap);
  va_end(ap);
  buf_add(b, tmp);
}

/* append s as a quoted SQL string literal */
static void
buf_addq(struct buf *b, const char *s) {
  char *q = PQescapeLiteral(g_conn, s, strlen(s));
  if (q == NULL) {
    b->fail = true;
    return;
  }
  buf_add(b, q);
  PQfreemem(q);
}

struct row {
  char *id;
  char *raw;
};

static bool
db_query(const cJSON *filter,
         int (*emit)(const char *id, const char *raw, void *ud),
         void *ud) {
  struct buf b = {NULL, 0, 0, false};
  const cJSON *f;
  int limit = 500, i, nrows = 0, cap = 0;
  bool none = false, ok = true;
  struct row *rows = NULL;

  if (!cJSON_IsObject(filter)) return false;

  pthread_mutex_lock(&g_mutex);
  buf_add(&b, "SELECT id, raw FROM event WHERE TRUE");
  for (f = filter->child; f != NULL; f = f->next) {
    const char *key = f->string;
    const cJSON *e;
    int n = 0;
    if (key == NULL) continue;
    if (strcmp(key, "ids") == 0 || strcmp(key, "authors") == 0) {
      if (!cJSON_IsArray(f)) { none = true; continue; }
      buf_addf(&b, " AND %s IN (", key[0] == 'i' ? "id" : "pubkey");
      for (e = f->child; e != NULL; e = e->next)
        if (cJSON_IsString(e)) {
          if (n++) buf_add(&b, ",");
          buf_addq(&b, e->valuestring);
        }
      buf_add(&b, ")");
      if (n == 0) none = true;
    } else if (strcmp(key, "kinds") == 0) {
      if (!cJSON_IsArray(f)) { none = true; continue; }
      buf_add(&b, " AND kind IN (");
      for (e = f->child; e != NULL; e = e->next)
        if (cJSON_IsNumber(e))
          buf_addf(&b, "%s%d", n++ ? "," : "", (int)e->valuedouble);
      buf_add(&b, ")");
      if (n == 0) none = true;
    } else if (strcmp(key, "since") == 0 && cJSON_IsNumber(f)) {
      buf_addf(&b, " AND created_at >= %lld", (long long)f->valuedouble);
    } else if (strcmp(key, "until") == 0 && cJSON_IsNumber(f)) {
      buf_addf(&b, " AND created_at <= %lld", (long long)f->valuedouble);
    } else if (strcmp(key, "limit") == 0 && cJSON_IsNumber(f)) {
      limit = (int)f->valuedouble;
    } else if (key[0] == '#' && key[1] != '\0') {
      if (!cJSON_IsArray(f)) { none = true; continue; }
      buf_add(&b, " AND EXISTS (SELECT 1 FROM tag WHERE"
                  " tag.event_id = event.id AND tag.name = ");
      buf_addq(&b, key + 1);
      buf_add(&b, " AND tag.value IN (");
      for (e = f->child; e != NULL; e = e->next)
        if (cJSON_IsString(e)) {
          if (n++) buf_add(&b, ",");
          buf_addq(&b, e->valuestring);
        }
      buf_add(&b, "))");
      if (n == 0) none = true;
    }
  }
  if (limit < 1) limit = 1;
  if (limit > 1000) limit = 1000;
  buf_addf(&b, " ORDER BY created_at DESC, id ASC LIMIT %d", limit);

  if (b.fail || b.s == NULL) {
    ok = false;
  } else if (!none) {
    PGresult *r = run(b.s, 0, NULL);
    if (r == NULL) {
      ok = false;
    } else {
      int nt = PQntuples(r);
      for (i = 0; i < nt; i++) {
        if (nrows == cap) {
          cap = cap ? cap * 2 : 64;
          rows = realloc(rows, sizeof(struct row) * cap);
        }
        rows[nrows].id = strdup(PQgetvalue(r, i, 0));
        rows[nrows].raw = strdup(PQgetvalue(r, i, 1));
        nrows++;
      }
      PQclear(r);
    }
  }
  free(b.s);
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

void
store_backend_postgresql(struct store_backend *be) {
  be->init = db_init;
  be->close = db_close;
  be->event = db_event;
  be->query = db_query;
}
