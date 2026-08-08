#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>

#define MAX_HTTP_HEAD (8 * 1024)
/* a client that stops reading gets this much queued before being dropped */
#define MAX_OUTBUF (16 * 1024 * 1024)

struct buf {
  unsigned char *p;
  size_t len, cap, off; /* off: already-written prefix (out buffer only) */
};

enum conn_state { ST_HTTP, ST_WS };

struct net_conn {
  int fd;
  enum conn_state state;
  bool opened;     /* ws_open was delivered */
  bool want_close; /* close once out drains */
  bool dead;       /* close now, discard out */
  struct buf in, out;
  int msg_op; /* opcode of the fragmented message in progress, 0 if none */
  struct buf msg;
  void *ud;
  struct net_conn *next;
};

static struct net_conn *g_conns;
static const struct net_callbacks *g_cb;
static size_t g_max_message;
static volatile sig_atomic_t g_net_stop;

void
net_stop(void) {
  g_net_stop = 1;
}

void
net_conn_set_ud(struct net_conn *c, void *ud) {
  c->ud = ud;
}

void *
net_conn_get_ud(struct net_conn *c) {
  return c->ud;
}

void
net_conn_close(struct net_conn *c) {
  c->want_close = true;
}

/* --- buffers ------------------------------------------------------------ */

static bool
buf_append(struct buf *b, const void *data, size_t n) {
  if (b->len + n > b->cap) {
    size_t cap = b->cap ? b->cap : 4096;
    unsigned char *p;
    while (b->len + n > cap) cap *= 2;
    p = realloc(b->p, cap);
    if (p == NULL) return false;
    b->p = p;
    b->cap = cap;
  }
  memcpy(b->p + b->len, data, n);
  b->len += n;
  return true;
}

static void
buf_consume(struct buf *b, size_t n) {
  memmove(b->p, b->p + n, b->len - n);
  b->len -= n;
}

static void
buf_free(struct buf *b) {
  free(b->p);
  memset(b, 0, sizeof *b);
}

/* queue outgoing bytes; overflow marks the connection for dropping */
static void
out_append(struct net_conn *c, const void *data, size_t n) {
  if (c->dead) return;
  if (c->out.len - c->out.off + n > MAX_OUTBUF || !buf_append(&c->out, data, n))
    c->dead = true;
}

/* --- websocket sending -------------------------------------------------- */

static void
ws_send_frame(struct net_conn *c, int op, const void *payload, size_t n) {
  unsigned char hdr[10];
  size_t h = 2;
  hdr[0] = 0x80 | (op & 0x0f);
  if (n < 126) {
    hdr[1] = (unsigned char)n;
  } else if (n < 65536) {
    hdr[1] = 126;
    hdr[2] = (unsigned char)(n >> 8);
    hdr[3] = (unsigned char)n;
    h = 4;
  } else {
    int i;
    hdr[1] = 127;
    for (i = 0; i < 8; i++)
      hdr[2 + i] = (unsigned char)((unsigned long long)n >> (56 - 8 * i));
    h = 10;
  }
  out_append(c, hdr, h);
  out_append(c, payload, n);
}

void
net_ws_send_text(struct net_conn *c, const char *s, size_t n) {
  if (c->state == ST_WS && !c->want_close) ws_send_frame(c, 0x1, s, n);
}

/* --- http --------------------------------------------------------------- */

void
net_http_respond(struct net_conn *c, int status, const char *content_type,
                 const char *extra_headers, const char *body, size_t len) {
  char head[512];
  const char *reason = status == 200   ? "OK"
                       : status == 404 ? "Not Found"
                                       : "Error";
  int n = snprintf(head, sizeof head,
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Type: %s\r\n"
                   "%s"
                   "Content-Length: %zu\r\n"
                   "Connection: close\r\n\r\n",
                   status, reason, content_type,
                   extra_headers != NULL ? extra_headers : "", len);
  out_append(c, head, (size_t)n);
  out_append(c, body, len);
  c->want_close = true;
}

/* find the first \r\n\r\n; -1 when incomplete */
static long
find_head_end(const unsigned char *p, size_t n) {
  size_t i;
  for (i = 0; i + 3 < n; i++)
    if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' && p[i + 3] == '\n')
      return (long)(i + 4);
  return -1;
}

/* copy a header value out of a NUL-terminated request head */
static bool
get_header(const char *head, const char *name, char *out, size_t outlen) {
  size_t nlen = strlen(name);
  const char *p = head;
  while ((p = strstr(p, "\r\n")) != NULL) {
    p += 2;
    if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
      const char *v = p + nlen + 1, *e;
      size_t n;
      while (*v == ' ' || *v == '\t') v++;
      e = strstr(v, "\r\n");
      if (e == NULL) return false;
      n = (size_t)(e - v);
      if (n >= outlen) n = outlen - 1;
      memcpy(out, v, n);
      out[n] = '\0';
      return true;
    }
  }
  return false;
}

static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static void
ws_accept_key(const char *key, char *out /* >= 29 bytes */) {
  unsigned char cat[128], md[EVP_MAX_MD_SIZE];
  unsigned int mdlen = 0;
  int n = snprintf((char *)cat, sizeof cat, "%s%s", key, WS_GUID);
  EVP_Digest(cat, (size_t)n, md, &mdlen, EVP_sha1(), NULL);
  EVP_EncodeBlock((unsigned char *)out, md, (int)mdlen);
}

static void
http_process(struct net_conn *c) {
  long headlen = find_head_end(c->in.p, c->in.len);
  char method[16], path[256], upgrade[64], key[64], accept[256];
  char *head, *sp1, *sp2, *q;

  if (headlen < 0) {
    if (c->in.len > MAX_HTTP_HEAD) c->dead = true;
    return;
  }
  head = malloc((size_t)headlen + 1);
  if (head == NULL) {
    c->dead = true;
    return;
  }
  memcpy(head, c->in.p, (size_t)headlen);
  head[headlen] = '\0';
  buf_consume(&c->in, (size_t)headlen);

  /* request line: METHOD SP PATH SP HTTP/x.y */
  sp1 = strchr(head, ' ');
  sp2 = sp1 != NULL ? strchr(sp1 + 1, ' ') : NULL;
  if (sp1 == NULL || sp2 == NULL || strstr(head, "\r\n") < sp2) {
    free(head);
    c->dead = true;
    return;
  }
  snprintf(method, sizeof method, "%.*s", (int)(sp1 - head), head);
  snprintf(path, sizeof path, "%.*s", (int)(sp2 - sp1 - 1), sp1 + 1);
  q = strchr(path, '?');
  if (q != NULL) *q = '\0';

  if (get_header(head, "Upgrade", upgrade, sizeof upgrade) &&
      strcasecmp(upgrade, "websocket") == 0 &&
      get_header(head, "Sec-WebSocket-Key", key, sizeof key)) {
    char akey[32], resp[256];
    int n;
    ws_accept_key(key, akey);
    n = snprintf(resp, sizeof resp,
                 "HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Accept: %s\r\n\r\n",
                 akey);
    out_append(c, resp, (size_t)n);
    c->state = ST_WS;
    c->opened = true;
    free(head);
    if (g_cb->ws_open != NULL) g_cb->ws_open(c);
    return;
  }

  if (!get_header(head, "Accept", accept, sizeof accept)) accept[0] = '\0';
  free(head);
  if (g_cb->http_request != NULL)
    g_cb->http_request(c, method, path, accept);
  else
    c->dead = true;
}

/* --- websocket receiving ------------------------------------------------ */

static void
ws_process(struct net_conn *c) {
  while (!c->dead && !c->want_close) {
    unsigned char *p = c->in.p;
    size_t avail = c->in.len, hdr = 2, i;
    unsigned long long plen;
    unsigned char mask[4];
    bool fin, masked;
    int op;

    if (avail < 2) return;
    fin = (p[0] & 0x80) != 0;
    op = p[0] & 0x0f;
    masked = (p[1] & 0x80) != 0;
    plen = p[1] & 0x7f;
    if (plen == 126) {
      if (avail < 4) return;
      plen = ((unsigned long long)p[2] << 8) | p[3];
      hdr = 4;
    } else if (plen == 127) {
      if (avail < 10) return;
      plen = 0;
      for (i = 0; i < 8; i++) plen = (plen << 8) | p[2 + i];
      hdr = 10;
    }
    /* client frames must be masked (RFC 6455); a huge length is either
     * abuse or a protocol error, both of which end the connection */
    if (!masked || plen > g_max_message + 16) {
      c->dead = true;
      return;
    }
    if (avail < hdr + 4 + plen) return;
    memcpy(mask, p + hdr, 4);
    hdr += 4;
    for (i = 0; i < plen; i++) p[hdr + i] ^= mask[i % 4];

    switch (op) {
    case 0x8: /* close: echo it back, then flush and close */
      ws_send_frame(c, 0x8, p + hdr, plen > 125 ? 0 : (size_t)plen);
      c->want_close = true;
      break;
    case 0x9: /* ping */
      ws_send_frame(c, 0xA, p + hdr, plen > 125 ? 0 : (size_t)plen);
      break;
    case 0xA: /* pong */
      break;
    case 0x0: /* continuation */
    case 0x1: /* text */
    case 0x2: /* binary */
      if (op != 0x0) {
        if (c->msg_op != 0) { /* new message while one is in progress */
          c->dead = true;
          return;
        }
        c->msg_op = op;
      } else if (c->msg_op == 0) {
        c->dead = true;
        return;
      }
      if (c->msg.len + plen > g_max_message) {
        if (g_cb->ws_overflow != NULL) g_cb->ws_overflow(c);
        c->want_close = true;
        break;
      }
      if (!buf_append(&c->msg, p + hdr, (size_t)plen)) {
        c->dead = true;
        return;
      }
      if (fin) {
        if (c->msg_op == 0x1 && g_cb->ws_message != NULL)
          g_cb->ws_message(c, (const char *)c->msg.p, c->msg.len);
        c->msg.len = 0; /* binary messages are read and dropped */
        c->msg_op = 0;
      }
      break;
    default: /* reserved opcode */
      c->dead = true;
      return;
    }
    buf_consume(&c->in, hdr + (size_t)plen);
  }
}

/* --- the loop ----------------------------------------------------------- */

static void
conn_flush(struct net_conn *c) {
  while (c->out.off < c->out.len) {
    ssize_t n = send(c->fd, c->out.p + c->out.off, c->out.len - c->out.off,
                     MSG_NOSIGNAL);
    if (n > 0) {
      c->out.off += (size_t)n;
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
    c->dead = true;
    return;
  }
  c->out.off = c->out.len = 0;
}

static void
conn_read(struct net_conn *c) {
  unsigned char tmp[65536];
  for (;;) {
    ssize_t n = recv(c->fd, tmp, sizeof tmp, 0);
    if (n > 0) {
      if (!buf_append(&c->in, tmp, (size_t)n)) {
        c->dead = true;
        return;
      }
      if (c->state == ST_HTTP) http_process(c);
      if (c->state == ST_WS) ws_process(c);
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
    c->dead = true; /* EOF or error */
    return;
  }
}

static void
conn_destroy(struct net_conn *c) {
  if (c->opened && g_cb->ws_close != NULL) g_cb->ws_close(c);
  close(c->fd);
  buf_free(&c->in);
  buf_free(&c->out);
  buf_free(&c->msg);
  free(c);
}

static int
make_listener(int port) {
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  int one = 1, zero = 0;
  if (fd >= 0) {
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in6 a6;
    memset(&a6, 0, sizeof a6);
    a6.sin6_family = AF_INET6;
    a6.sin6_addr = in6addr_any;
    a6.sin6_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&a6, sizeof a6) == 0 &&
        listen(fd, 128) == 0)
      return fd;
    close(fd);
  }
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in a4;
  memset(&a4, 0, sizeof a4);
  a4.sin_family = AF_INET;
  a4.sin_addr.s_addr = htonl(INADDR_ANY);
  a4.sin_port = htons((unsigned short)port);
  if (bind(fd, (struct sockaddr *)&a4, sizeof a4) != 0 ||
      listen(fd, 128) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static void
set_nonblock(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

bool
net_serve(int port, const struct net_callbacks *cb, size_t max_message) {
  int lfd = make_listener(port);
  struct pollfd *pfds = NULL;
  size_t pcap = 0;

  if (lfd < 0) return false;
  set_nonblock(lfd);
  g_cb = cb;
  g_max_message = max_message;
  signal(SIGPIPE, SIG_IGN);

  while (!g_net_stop) {
    struct net_conn *c, **pp;
    size_t n = 1, i;

    for (c = g_conns; c != NULL; c = c->next) n++;
    if (n > pcap) {
      struct pollfd *np = realloc(pfds, n * sizeof *np);
      if (np == NULL) break;
      pfds = np;
      pcap = n;
    }
    pfds[0].fd = lfd;
    pfds[0].events = POLLIN;
    for (i = 1, c = g_conns; c != NULL; c = c->next, i++) {
      pfds[i].fd = c->fd;
      pfds[i].events = (short)((c->want_close ? 0 : POLLIN) |
                               (c->out.off < c->out.len ? POLLOUT : 0));
    }

    if (poll(pfds, (nfds_t)n, 200) < 0) {
      if (errno == EINTR) continue;
      break;
    }

    /* handlers only set flags and append to buffers, so the list layout
     * matches pfds for the whole walk; new connections are accepted after */
    for (i = 1, c = g_conns; c != NULL; c = c->next, i++) {
      if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) c->dead = true;
      if (!c->dead && (pfds[i].revents & POLLIN)) conn_read(c);
    }

    if (pfds[0].revents & POLLIN) {
      for (;;) {
        int fd = accept(lfd, NULL, NULL);
        struct net_conn *nc;
        if (fd < 0) break;
        set_nonblock(fd);
        nc = calloc(1, sizeof *nc);
        if (nc == NULL) {
          close(fd);
          continue;
        }
        nc->fd = fd;
        nc->state = ST_HTTP;
        nc->next = g_conns;
        g_conns = nc;
      }
    }

    /* handlers may have queued data on any connection */
    for (c = g_conns; c != NULL; c = c->next)
      if (!c->dead) conn_flush(c);

    for (pp = &g_conns; *pp != NULL;) {
      c = *pp;
      if (c->dead || (c->want_close && c->out.off >= c->out.len)) {
        *pp = c->next;
        conn_destroy(c);
      } else {
        pp = &c->next;
      }
    }
  }

  while (g_conns != NULL) {
    struct net_conn *c = g_conns;
    g_conns = c->next;
    conn_destroy(c);
  }
  free(pfds);
  close(lfd);
  return true;
}
