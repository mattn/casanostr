# syntax=docker/dockerfile:1.4

FROM alpine:3.20 AS build-dev
RUN apk add --no-cache \
    gcc \
    musl-dev \
    cmake \
    make \
    git \
    pkgconf \
    libsecp256k1-dev \
    sqlite-dev \
    openssl-dev \
    libpq-dev \
    linux-headers
WORKDIR /usr/src/app
COPY . /usr/src/app
RUN git submodule update --init --recommend-shallow --depth 1

RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make casanostr
# Verify dynamic linking
RUN ldd build/casanostr

FROM alpine:3.20 AS build-run
RUN apk add --no-cache \
    libsecp256k1 \
    libpq \
    openssl \
    sqlite-libs \
    ca-certificates
COPY --from=build-dev /usr/src/app/build/casanostr /usr/bin/casanostr
RUN mkdir /data
WORKDIR /data
EXPOSE 7447
# stores /data/casanostr.db unless -d or DATABASE_URL selects another database
ENTRYPOINT ["/usr/bin/casanostr"]
