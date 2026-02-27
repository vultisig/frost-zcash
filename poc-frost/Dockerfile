FROM rust:1.83-bookworm AS rust-builder

WORKDIR /build
COPY frost-zcash/Cargo.toml frost-zcash/rust-toolchain.toml ./
COPY frost-zcash/frost-lib/ frost-lib/
COPY frost-zcash/frost-wasm/ frost-wasm/

RUN cargo build --release -p frost-lib

FROM golang:1.22-bookworm AS go-builder

COPY --from=rust-builder /build/target/release/libfrostlib.so /usr/lib/
RUN ldconfig

WORKDIR /build
COPY frost-zcash/go-frost/ go-frost/
COPY frost-zcash/poc-frost/ poc-frost/

COPY --from=rust-builder /build/frost-lib/include/frost-lib.h go-frost/includes/
RUN mkdir -p go-frost/includes/linux && \
    cp /usr/lib/libfrostlib.so go-frost/includes/linux/

WORKDIR /build/poc-frost
RUN CGO_ENABLED=1 go build -o /frost-party ./cmd/frost-party

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /build/target/release/libfrostlib.so /usr/lib/
RUN ldconfig

COPY --from=go-builder /frost-party /usr/local/bin/frost-party

RUN mkdir -p /data/keystore

ENTRYPOINT ["frost-party"]
