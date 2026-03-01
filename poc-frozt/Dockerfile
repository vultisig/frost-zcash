FROM rust:1.83-bookworm AS rust-builder

WORKDIR /build
COPY frost-zcash/Cargo.toml frost-zcash/rust-toolchain.toml ./
COPY frost-zcash/frozt-lib/ frozt-lib/
COPY frost-zcash/frozt-wasm/ frozt-wasm/

RUN cargo build --release -p frozt-lib

FROM golang:1.24-bookworm AS go-builder

COPY --from=rust-builder /build/target/release/libfroztlib.so /usr/lib/
RUN ldconfig

WORKDIR /build
COPY frost-zcash/go-frozt/ go-frozt/
COPY frost-zcash/poc-frozt/ poc-frozt/

COPY --from=rust-builder /build/frozt-lib/include/frozt-lib.h go-frozt/includes/
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then LIBDIR=linux-amd64; else LIBDIR=linux-arm64; fi && \
    mkdir -p go-frozt/includes/$LIBDIR && \
    cp /usr/lib/libfroztlib.so go-frozt/includes/$LIBDIR/

WORKDIR /build/poc-frozt
RUN CGO_ENABLED=1 go build -o /frozt-party ./cmd/frozt-party

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /build/target/release/libfroztlib.so /usr/lib/
RUN ldconfig

COPY --from=go-builder /frozt-party /usr/local/bin/frozt-party

RUN mkdir -p /data/keystore

ENTRYPOINT ["frozt-party"]
