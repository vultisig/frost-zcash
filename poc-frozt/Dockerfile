FROM rust:1.83-bookworm AS rust-builder

WORKDIR /build
COPY frozt-zcash/Cargo.toml frozt-zcash/rust-toolchain.toml ./
COPY frozt-zcash/frozt-lib/ frozt-lib/
COPY frozt-zcash/frozt-wasm/ frozt-wasm/

RUN cargo build --release -p frozt-lib

FROM golang:1.22-bookworm AS go-builder

COPY --from=rust-builder /build/target/release/libfroztlib.so /usr/lib/
RUN ldconfig

WORKDIR /build
COPY frozt-zcash/go-frozt/ go-frozt/
COPY frozt-zcash/poc-frozt/ poc-frozt/

COPY --from=rust-builder /build/frozt-lib/include/frozt-lib.h go-frozt/includes/
RUN mkdir -p go-frozt/includes/linux && \
    cp /usr/lib/libfroztlib.so go-frozt/includes/linux/

WORKDIR /build/poc-frozt
RUN CGO_ENABLED=1 go build -o /frozt-party ./cmd/frozt-party

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /build/target/release/libfroztlib.so /usr/lib/
RUN ldconfig

COPY --from=go-builder /frozt-party /usr/local/bin/frozt-party

RUN mkdir -p /data/keystore

ENTRYPOINT ["frozt-party"]
