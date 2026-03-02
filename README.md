# frozt

FROZT (Flexible Round-Optimized Zcash-Schnorr Threshold) signatures for Zcash Sapling. Enables T-of-N threshold signing on the RedJubjub curve (`JubjubBlake2b512`) with rerandomization, so a group of N parties can collectively sign Zcash shielded transactions without any single party ever holding the full private key. Supports importing existing Zcash Sapling spending keys (derived from BIP39 seed phrases via ZIP 32) into the threshold scheme.

## Architecture

```
frozt-wasm/     WebAssembly bindings (wasm-bindgen, for browsers)
frozt-lib/      Rust core library with C FFI (cdylib)
go-frozt/       Go bindings via CGo + orchestration layer
poc-frozt/      Docker-based proof-of-concept (3-party demo)
```

### frozt-lib

The cryptographic core. Implements three FROZT protocols over the `reddsa` crate's RedJubjub ciphersuite:

- **DKG (Distributed Key Generation)** — 3-round protocol (`frozt_dkg_part1/2/3`) where N parties jointly generate a shared key. Each party receives a `KeyPackage` (their private signing share) and a `PublicKeyPackage` (the group verifying key).
- **Signing** — 4-phase rerandomized threshold signing (`frozt_sign_commit`, `frozt_sign_new_package`, `frozt_sign`, `frozt_sign_aggregate`). Any T signers produce a valid RedJubjub signature. Rerandomization is required for Zcash Sapling's unlinkability guarantees.
- **Resharing** — Change the threshold scheme (e.g., 2-of-2 to 2-of-3) without changing the group verifying key (`frozt_reshare_part1`, reuses `frozt_dkg_part2`, `frozt_reshare_part3`).
- **Key Import** — Import an existing Zcash Sapling spending key into the threshold scheme (`frozt_derive_spending_key_from_seed`, `frozt_spending_key_to_verifying_key`, `frozt_key_import_part1`, reuses `frozt_dkg_part2`, `frozt_key_import_part3`). The importing party provides their spending key; all other parties participate with zero-knowledge. The result is verified against the expected verifying key.
- **Sapling** — Generate and manage Sapling extras (96 bytes: `nsk || ovk || dk`) needed for z-address derivation. For seedless DKG, extras are generated randomly (`frozt_sapling_generate_extras`). For key import, extras are derived from the original seed (`frozt_derive_sapling_extras_from_seed`). Z-addresses are derived by combining the group public key with sapling extras (`frozt_sapling_derive_address`).

Exposes all functions as `extern "C"` with a C header (`frozt-lib.h`). Intermediate secret state is held in a global handle table to avoid serializing sensitive material across the FFI boundary.

### go-frozt

Go package wrapping every C function with idiomatic Go APIs via CGo. Includes:

- **`frozt.go`** — Direct 1:1 wrappers for DKG, signing, resharing, key import, sapling extras, identifier encoding, key inspection, and address derivation.
- **`codec.go`** — Go implementation of the binary map serialization format (length-prefixed `{id, value}` entries).
- **`orchestration/`** — Multi-party coordination layer for running FROZT protocols across separate processes over a Vultisig relay server:
  - `relay_client.go` — HTTP client for session management, message passing, and barrier synchronization.
  - `keygen.go` / `sign.go` / `reshare.go` — Full protocol orchestrators that handle message routing, round barriers, and coordinator election.

### frozt-wasm

WebAssembly build of the same cryptographic operations via `wasm-bindgen`. Targets browsers with `getrandom/js` for randomness. Secrets are serialized between calls (no handle table). Returns JS objects with `Uint8Array` fields.

### poc-frozt

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
cargo build --release -p frozt-wasm --target wasm32-unknown-unknown
```

## Test

```bash
# Rust tests (DKG, signing, resharing, key import, address derivation)
make test-rust

# Go tests (full flow: DKG -> sign -> reshare -> sign -> key import -> sign)
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
cd poc-frozt
./scripts/run-keygen.sh my-session
./scripts/run-sign.sh my-session "hello zcash" "party-1,party-2"
```

## Upstream Sources

FROZT does not hand-roll cryptography. All cryptographic primitives come from peer-reviewed, published libraries maintained by the Zcash ecosystem:

| Component | Source | What it provides |
|-----------|--------|------------------|
| **FROST DKG & signing** | [`frost-core`](https://crates.io/crates/frost-core) v2.2 | Standard FROST distributed key generation and threshold signing |
| **Rerandomized signing** | [`frost-rerandomized`](https://crates.io/crates/frost-rerandomized) v2.2 | Rerandomization layer for Zcash Sapling unlinkability |
| **RedJubjub ciphersuite** | [`reddsa`](https://github.com/ZcashFoundation/reddsa) (ZcashFoundation) | `JubjubBlake2b512` curve + FROST ciphersuite definition |
| **Sapling key derivation** | [`sapling-crypto`](https://crates.io/crates/sapling-crypto) v0.6 | ZIP 32 extended spending keys, note encryption, Groth16 spend/output provers |
| **Address encoding** | [`zcash_address`](https://crates.io/crates/zcash_address) v0.6 | Bech32 Sapling z-address encoding |
| **JubJub field ops** | [`jubjub`](https://crates.io/crates/jubjub) v0.10 | Scalar field and group operations |
| **ZIP 32 paths** | [`zip32`](https://crates.io/crates/zip32) v0.2 | Hardened path derivation (`m/32'/133'/account'`) |

DKG delegates directly to `frost_core::keys::dkg::part1/2/3`. Signing delegates to `frost_rerandomized::sign` and `frost_rerandomized::aggregate`. Sapling key derivation delegates to `sapling_crypto::zip32::ExtendedSpendingKey`. Z-address generation delegates to `sapling_crypto::keys::DiversifiableFullViewingKey`. Groth16 proofs delegate to `sapling_crypto::prover::{SpendProver, OutputProver}`.

### What we do write ourselves (and why it's safe)

Three protocol extensions compose the upstream primitives without introducing new cryptographic assumptions:

**Resharing** (`reshare.rs`) — Allows changing the threshold scheme (e.g., 2-of-2 → 2-of-3) while preserving the group public key. The only custom math is computing Lagrange interpolation coefficients over the JubJub scalar field — textbook polynomial evaluation using upstream field arithmetic (`Fr::one()`, multiply, invert). The result feeds into standard `frost-core` DKG rounds 2 and 3. Output is verified against the expected group verifying key.

**Key Import** (`key_import.rs`) — Imports an existing Zcash Sapling spending key into the threshold scheme. The importing party sets their DKG polynomial constant to `ask - (N-1)` while all other parties use `1`, so the shares sum to the original spending key. This is a single field subtraction on top of standard ZIP 32 derivation (upstream `ExtendedSpendingKey::from_path`) and standard FROST DKG. The resulting group public key is verified against the expected verifying key derived from the spending key.

**Sapling extras & z-address composition** (`sapling.rs`) — Constructs a `DiversifiableFullViewingKey` by combining the FROST group public key with Sapling scalars (`nsk`, `ovk`, `dk`). For seed-based imports, these are extracted directly from the upstream `ExtendedSpendingKey`. For seedless DKG, `nsk` is generated via `jubjub::Fr::random()` and the rest via `OsRng`. The z-address itself is produced by upstream `DiversifiableFullViewingKey::default_address()`. The initiating party shares these extras (including view key material) with all other parties so each can derive the z-address; this is safe because all Vultisig vault parties are devices controlled by the same user — no untrusted party gains transaction visibility.

Everything else (FFI handle table, binary codec, Go/WASM bindings) is non-cryptographic plumbing.

## Protocol Details

### Curve & Ciphersuite

RedJubjub with Blake2b-512 (`JubjubBlake2b512`) — the curve used by Zcash Sapling for spend authorization signatures. The signing protocol uses `frost-rerandomized` to produce rerandomized signatures, which is essential for Zcash's privacy model.

### DKG

Standard FROZT DKG from `frost-core` v2.2:

1. **Round 1**: Each party generates a random polynomial of degree `t-1` and broadcasts a commitment + proof of knowledge.
2. **Round 2**: Each party evaluates their polynomial at every other party's identifier and sends the evaluation privately.
3. **Round 3**: Each party combines received evaluations to derive their signing share and the group verifying key.

### Resharing

Allows changing `(T, N)` while preserving the group verifying key:

- Old members compute `signing_share * lagrange_coefficient` as their polynomial's constant term.
- New members use a constant term of `1`.
- The lowest-ID old member subtracts `1` for each new member to cancel their contributions.
- Rounds 2 and 3 reuse the standard DKG protocol. The result is verified against the expected verifying key.

### Key Import

Import an existing Zcash Sapling spending key (derived from a BIP39 mnemonic via ZIP 32 hardened path `m/32'/133'/account'`) into the threshold scheme:

1. **Seed derivation**: `frozt_derive_spending_key_from_seed` takes a 64-byte BIP39 seed and account index, derives the `ask` (spend authorizing key) scalar via ZIP 32.
2. **Round 1**: The importing party (party 1) sets their polynomial's constant term to `ask - (N-1)`. All other parties set their constant term to `1`. The sum of all constants equals `ask`.
3. **Round 2**: Reuses `frozt_dkg_part2` unchanged.
4. **Round 3**: `frozt_key_import_part3` runs standard DKG part 3, then verifies the resulting group verifying key matches the expected key derived from the spending key.

Sapling extras (`nsk`, `ovk`, `dk`) needed for z-address derivation are extracted from the seed via `frozt_derive_sapling_extras_from_seed`. For seedless DKG, use `frozt_sapling_generate_extras` to produce random extras. In both cases, `frozt_sapling_derive_address` combines the group public key with the extras to produce a valid Sapling z-address.

**Note on view key sharing:** During key import, the initiating party derives the Sapling extras (which include view key material) from the seed and shares them with all other parties so that every party can independently derive the z-address. In a standard Zcash setup, sharing view keys would grant transaction visibility to those parties. In Vultisig's model this is acceptable because all parties in a vault are controlled by the same user across their own devices — there is no untrusted counter-party who would gain unwanted visibility into the user's transaction history.

### Signing

Rerandomized FROZT signing:

1. **Commit**: Each signer generates nonces and broadcasts commitments.
2. **Package**: Coordinator collects commitments, creates the signing package, and generates a randomizer.
3. **Sign**: Each signer produces a signature share.
4. **Aggregate**: Coordinator combines shares into a final valid RedJubjub signature.

## License

See individual crate licenses.
