# frost-zcash

FROST (Flexible Round-Optimized Schnorr Threshold) signatures for Zcash Sapling. Enables T-of-N threshold signing on the RedJubjub curve (`JubjubBlake2b512`) with rerandomization, so a group of N parties can collectively sign Zcash shielded transactions without any single party ever holding the full private key.

## Architecture

```
frost-wasm/     WebAssembly bindings (wasm-bindgen, for browsers)
frost-lib/      Rust core library with C FFI (cdylib)
go-frost/       Go bindings via CGo + orchestration layer
poc-frost/      Docker-based proof-of-concept (3-party demo)
```

### frost-lib

The cryptographic core. Implements three FROST protocols over the `reddsa` crate's RedJubjub ciphersuite:

- **DKG (Distributed Key Generation)** — 3-round protocol (`frost_dkg_part1/2/3`) where N parties jointly generate a shared key. Each party receives a `KeyPackage` (their private signing share) and a `PublicKeyPackage` (the group verifying key).
- **Signing** — 4-phase rerandomized threshold signing (`frost_sign_commit`, `frost_sign_new_package`, `frost_sign`, `frost_sign_aggregate`). Any T signers produce a valid RedJubjub signature. Rerandomization is required for Zcash Sapling's unlinkability guarantees.
- **Resharing** — Change the threshold scheme (e.g., 2-of-2 to 2-of-3) without changing the group verifying key (`frost_reshare_part1`, reuses `frost_dkg_part2`, `frost_reshare_part3`).
- **Address derivation** — Derive Zcash shielded z-addresses (Sapling, bech32 `zs...`) and transparent t-addresses (Base58Check `t1...`) from the group public key.

Exposes all functions as `extern "C"` with a C header (`frost-lib.h`). Intermediate secret state is held in a global handle table to avoid serializing sensitive material across the FFI boundary.

### go-frost

Go package wrapping every C function with idiomatic Go APIs via CGo. Includes:

- **`frost.go`** — Direct 1:1 wrappers for DKG, signing, resharing, identifier encoding, key inspection, and address derivation.
- **`codec.go`** — Go implementation of the binary map serialization format (length-prefixed `{id, value}` entries).
- **`orchestration/`** — Multi-party coordination layer for running FROST protocols across separate processes over a Vultisig relay server:
  - `relay_client.go` — HTTP client for session management, message passing, and barrier synchronization.
  - `keygen.go` / `sign.go` / `reshare.go` — Full protocol orchestrators that handle message routing, round barriers, and coordinator election.

### frost-wasm

WebAssembly build of the same cryptographic operations via `wasm-bindgen`. Targets browsers with `getrandom/js` for randomness. Secrets are serialized between calls (no handle table). Returns JS objects with `Uint8Array` fields.

### poc-frost

Docker Compose demo running 3 parties with a Vultisig relay server and Redis backend. Supports keygen and signing operations out of the box.

## Prerequisites

- Rust stable toolchain
- Go 1.22+
- Docker & Docker Compose (for the PoC)

## Build

```bash
# Build the Rust library
make build-rust

# Build Go bindings (copies .dylib/.so + header, then builds Go)
make build-go

# Build WASM package
cargo build --release -p frost-wasm --target wasm32-unknown-unknown
```

## Test

```bash
# Rust tests (DKG, signing, resharing, address derivation)
make test-rust

# Go tests (full flow: DKG -> sign -> reshare -> sign)
make test-go

# Both
make test

# Docker-based integration test (builds Rust + Go, runs all tests)
docker build -f Dockerfile.test .
```

## PoC: 3-Party Demo

Run a full 3-party keygen with Docker:

```bash
# Keygen (generates keys for 3 parties, 2-of-3 threshold)
make docker-keygen SESSION=my-session

# Sign (parties 1 and 2 sign a message using keys from the keygen session)
make docker-sign SESSION=my-session MESSAGE="hello zcash" SIGNERS="party-1,party-2"
```

Or use the scripts directly:

```bash
cd poc-frost
./scripts/run-keygen.sh my-session
./scripts/run-sign.sh my-session "hello zcash" "party-1,party-2"
```

## Protocol Details

### Curve & Ciphersuite

RedJubjub with Blake2b-512 (`JubjubBlake2b512`) — the curve used by Zcash Sapling for spend authorization signatures. The signing protocol uses `frost-rerandomized` to produce rerandomized signatures, which is essential for Zcash's privacy model.

### DKG

Standard FROST DKG from `frost-core` v2.2:

1. **Round 1**: Each party generates a random polynomial of degree `t-1` and broadcasts a commitment + proof of knowledge.
2. **Round 2**: Each party evaluates their polynomial at every other party's identifier and sends the evaluation privately.
3. **Round 3**: Each party combines received evaluations to derive their signing share and the group verifying key.

### Resharing

Allows changing `(T, N)` while preserving the group verifying key:

- Old members compute `signing_share * lagrange_coefficient` as their polynomial's constant term.
- New members use a constant term of `1`.
- The lowest-ID old member subtracts `1` for each new member to cancel their contributions.
- Rounds 2 and 3 reuse the standard DKG protocol. The result is verified against the expected verifying key.

### Signing

Rerandomized FROST signing:

1. **Commit**: Each signer generates nonces and broadcasts commitments.
2. **Package**: Coordinator collects commitments, creates the signing package, and generates a randomizer.
3. **Sign**: Each signer produces a signature share.
4. **Aggregate**: Coordinator combines shares into a final valid RedJubjub signature.

## License

See individual crate licenses.
