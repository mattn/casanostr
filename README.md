# casanostr

A [Nostr](https://github.com/nostr-protocol/nostr) relay written in C.

![casanostr](casanostr.png)

Named after Giacomo Casanova — a contemporary (and acquaintance) of
Alessandro Cagliostro, after whom [cagliostr](https://github.com/mattn/cagliostr),
the C++ sibling of this relay, is named.

## Features

- NIP-01: EVENT / REQ / CLOSE, replaceable, ephemeral and addressable events
- NIP-09: event deletion
- NIP-11: relay information document
- WebSocket: [civetweb](https://github.com/civetweb/civetweb) (git submodule, MIT)
- JSON: [cJSON](https://github.com/DaveGamble/cJSON) (git submodule, MIT)
- Signature verification: libsecp256k1 (BIP-340 schnorr)
- Storage: SQLite3 or PostgreSQL

TLS is intentionally not implemented; run behind a reverse proxy
(nginx, caddy, ...) to serve `wss://`.

## Requirements

```
apt install cmake pkg-config libsecp256k1-dev libsqlite3-dev libssl-dev libpq-dev
```

(OpenSSL is used only for SHA-256 / the websocket handshake SHA-1.)

## Build

```
git submodule update --init
cmake -B build
cmake --build build
```

## Usage

```
./casanostr [-p port] [-d dbfile|postgres://...]
```

Defaults: port 7447, database `casanostr.db`.

`-d` accepts either a SQLite file path or a PostgreSQL connection URL
(`postgres://user:pass@host:5432/dbname`). The `DATABASE_URL`
environment variable is used when `-d` is not given.

## Test

```
ctest --test-dir build
```

Requires python3 and curl.

## License

MIT

Bundled libraries (git submodules under `deps/`) keep their own licenses.

`casanostr.png` is a portrait of Giacomo Casanova by Francesco Narici
(18th century, public domain), via
[Wikimedia Commons](https://commons.wikimedia.org/wiki/File:Giacomo_Casanova_by_Francesco_Narici.jpg).

## Author

Yasuhiro Matsumoto (a.k.a. mattn)
