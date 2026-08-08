#ifndef CASANOSTR_NET_H
#define CASANOSTR_NET_H

#include <stdbool.h>
#include <stddef.h>

/* Single-threaded poll(2) event loop serving HTTP and WebSocket on one
 * port.  Callbacks run on the loop thread; sends only append to a
 * connection's output buffer, so they are safe from any callback. */

struct net_conn;

struct net_callbacks {
  /* a connection finished the websocket handshake */
  void (*ws_open)(struct net_conn *c);
  /* a complete text message arrived */
  void (*ws_message)(struct net_conn *c, const char *data, size_t len);
  /* a message grew past the size limit; the connection closes afterwards */
  void (*ws_overflow)(struct net_conn *c);
  /* the connection is going away; free any user data */
  void (*ws_close)(struct net_conn *c);
  /* a plain HTTP request; answer with net_http_respond */
  void (*http_request)(struct net_conn *c, const char *method,
                       const char *path, const char *accept);
};

/* Run the loop until net_stop(); returns false when the port cannot be
 * bound.  max_message caps a reassembled websocket message. */
bool net_serve(int port, const struct net_callbacks *cb, size_t max_message);
void net_stop(void);

void net_ws_send_text(struct net_conn *c, const char *s, size_t n);
void net_http_respond(struct net_conn *c, int status, const char *content_type,
                      const char *extra_headers, const char *body, size_t len);
/* close once the output buffer has drained */
void net_conn_close(struct net_conn *c);

void net_conn_set_ud(struct net_conn *c, void *ud);
void *net_conn_get_ud(struct net_conn *c);

#endif
