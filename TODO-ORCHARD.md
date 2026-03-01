# Orchard Integration: Technical Implementation Plan

This document describes the top-to-bottom implementation for adding Zcash Orchard
(Pallas curve / Halo 2) support alongside the existing Sapling (Jubjub / Groth16) support.

## Table of Contents

- [Overview](#overview)
- [Phase 1: Orchard DKG + Key Import + Signing](#phase-1-orchard-dkg--key-import--signing)
- [Phase 2: Orchard Key Derivation + Addresses](#phase-2-orchard-key-derivation--addresses)
- [Phase 3: Orchard Transaction Building](#phase-3-orchard-transaction-building)
- [Phase 4: Orchard Note Scanning + Tree](#phase-4-orchard-note-scanning--tree)
- [Phase 5: Go + WASM Bindings](#phase-5-go--wasm-bindings)
- [Phase 6: Orchestration + Dual-Pool Ceremony](#phase-6-orchestration--dual-pool-ceremony)
- [Appendix: Cryptographic Reference](#appendix-cryptographic-reference)
- [Appendix: Dependency Changes](#appendix-dependency-changes)
- [Appendix: Blockers and Risks](#appendix-blockers-and-risks)

---

## Overview

### Why Orchard

- Orchard is the active shielded pool (~4.2M ZEC vs ~636K in Sapling)
- No trusted setup (Halo 2 eliminates Groth16 parameter files)
- Actions are arity-hiding (observer cannot distinguish spends from outputs)
- NU7 (ZSA, network sustainability) builds on Orchard, not Sapling
- Sapling is not deprecated but is the legacy pool

### Architecture Principle

Orchard is **purely additive**. All existing Sapling code remains unchanged. New modules
are added in parallel with `_orchard_` prefixed FFI function names.

### Curve Difference

| Property | Sapling | Orchard |
|---|---|---|
| Application curve | Jubjub (embedded in BLS12-381) | Pallas |
| Proof curve | BLS12-381 | Vesta |
| Signature scheme | RedJubjub | RedPallas |
| FROST ciphersuite | `JubjubBlake2b512` | `PallasBlake2b512` |
| Curve order | Cofactor 8 | Prime order (cofactor 1) |

---

## Phase 1: Orchard DKG + Key Import + Signing

**Priority: HIGH - should be implemented now to future-proof DKG ceremonies.**

DKG is the coordination bottleneck (all parties must be online simultaneously).
By running Jubjub and Pallas DKGs in the same ceremony, users get both key sets
without a second ceremony later.

### 1.1 New Rust Modules

Create parallel modules that use `PallasBlake2b512` instead of `JubjubBlake2b512`:

#### `frozt-lib/src/keygen_orchard.rs`

Duplicate of `keygen.rs` with:
```rust
use reddsa::frost::redpallas::PallasBlake2b512;
type P = PallasBlake2b512;
type Identifier = frost_core::Identifier<P>;
```

Exported functions (identical signatures to Sapling, different ciphersuite):
- `frozt_orchard_dkg_part1(identifier, max_signers, min_signers, out_secret, out_package)`
- `frozt_orchard_dkg_part2(secret, round1_packages, out_secret, out_packages)`
- `frozt_orchard_dkg_part3(secret, round1_packages, round2_packages, out_key_package, out_pub_key_package)`

Helper functions to export for reuse:
- `decode_r1_map_orchard()` - decode round1 packages with `P` ciphersuite
- `encode_r2_map_orchard()` - encode round2 packages with `P` ciphersuite
- `decode_r2_map_orchard()` - decode round2 packages with `P` ciphersuite

Note: The `reddsa` PallasBlake2b512 ciphersuite automatically enforces even-Y on the
group verifying key via a `post_dkg` hook. No manual correction needed.

#### `frozt-lib/src/sign_orchard.rs`

Duplicate of `sign.rs` with `type P = PallasBlake2b512`.

Exported functions:
- `frozt_orchard_sign_commit(key_package, out_nonces, out_commitments)`
- `frozt_orchard_sign_new_package(message, commitments_map, pub_key_package, out_signing_package, out_randomizer_seed)`
- `frozt_orchard_sign(signing_package, nonces, key_package, randomizer_seed, out_share)`
- `frozt_orchard_sign_aggregate(signing_package, shares_map, pub_key_package, randomizer_seed, out_signature)`
- `frozt_orchard_generate_randomizer(out_randomizer)`
- `frozt_orchard_sign_create_package(message, commitments_map, out_signing_package)`
- `frozt_orchard_compute_rk(pub_key_package, randomizer, out_rk)`

#### `frozt-lib/src/key_import_orchard.rs`

Orchard spending key derivation from BIP39 seed + FROST key import.

**`frozt_orchard_derive_spending_key_from_seed(seed, account_index, out_spending_key)`**

Derivation steps:
1. ZIP32 hardened derivation with personalization `"ZcashIP32Orchard"` and child
   domain byte `0x81`, path `m/32'/133'/account'`
2. Produces 32-byte opaque spending key `sk`
3. Derive `ask` via `BLAKE2b-512("Zcash_ExpandSeed", sk || 0x06)` -> 64 bytes
4. Reduce to Pallas scalar: `pallas::Scalar::from_uniform_bytes(&output)`
5. Even-Y correction: if `[ask] * G` has odd Y (high bit of serialized point = 1),
   negate `ask` to `-ask`
6. Return the 32-byte `ask` scalar (this is what FROST splits into shares)

Implementation detail: The `zip32` crate (v0.2) provides `zip32::hardened_only::HardenedOnlyKey`
with a `Context` trait. We implement the Orchard context:
```rust
struct OrchardZip32;
impl zip32::hardened_only::Context for OrchardZip32 {
    const MKG_DOMAIN: [u8; 16] = *b"ZcashIP32Orchard";
    const CKD_DOMAIN: ... = PrfExpand::ORCHARD_ZIP32_CHILD; // domain byte 0x81
}
```

If `zip32::hardened_only` does not expose the required traits publicly, derive manually
using `blake2b_simd` (already a dependency):
```
master_key = BLAKE2b-256(personalization="ZcashIP32Orchard", input=seed)
child derivation via BLAKE2b PRF with domain byte 0x81 per path component
```

**`frozt_orchard_spending_key_to_verifying_key(spending_key, out_verifying_key)`**

```rust
let ask = pallas::Scalar::from_repr(spending_key_bytes);
let ak = pallas::Point::generator() * ask;
// Even-Y normalization (if ak serialized high bit = 1, negate)
```

**`frozt_orchard_key_import_part1(identifier, max_signers, min_signers, spending_key, out_secret, out_package)`**

Identical logic to Sapling `frozt_key_import_part1` but parameterized on `PallasBlake2b512`.
The constant term adjustment (`a0 = spending_key - (max_signers - 1) * 1`) works identically
on the Pallas scalar field.

**`frozt_orchard_key_import_part3(secret, round1_packages, round2_packages, expected_vk, out_key_package, out_pub_key_package)`**

Same as Sapling variant. Uses `decode_r1_map_orchard` / `decode_r2_map_orchard`.
Verifies resulting group verifying key matches `expected_vk`.

#### `frozt-lib/src/reshare_orchard.rs`

Duplicate of `reshare.rs` with `type P = PallasBlake2b512`.

- `frozt_orchard_reshare_part1(identifier, max_signers, min_signers, old_key_package, old_identifiers, out_secret, out_package)`
- `frozt_orchard_reshare_part3(secret, round1_packages, round2_packages, expected_vk, out_key_package, out_pub_key_package)`

Lagrange coefficient computation and additive share logic work identically on Pallas scalars.

#### `frozt-lib/src/keyshare_orchard.rs`

Duplicate of `keyshare.rs` with `type P = PallasBlake2b512`.

- `frozt_orchard_encode_identifier(id, out_bytes)`
- `frozt_orchard_decode_identifier(id_bytes, out_id)`
- `frozt_orchard_keypackage_identifier(key_package, out_id)`
- `frozt_orchard_pubkeypackage_verifying_key(pub_key_package, out_key)`

Note: Identifier serialization may differ between ciphersuites. The Pallas identifier
uses a different scalar field, so the serialized bytes will be different for the same u16.

### 1.2 Update `frozt-lib/src/lib.rs`

```rust
mod keygen_orchard;
mod sign_orchard;
mod key_import_orchard;
mod reshare_orchard;
mod keyshare_orchard;
```

### 1.3 Update C Header (`frozt-lib/include/frozt-lib.h`)

Add all `frozt_orchard_*` function declarations mirroring the existing Sapling ones.
Add `LIB_ORCHARD_ERROR` to the `lib_error` enum.

### 1.4 Tests

Each new module gets a parallel test suite:
- `test_orchard_dkg_2x3` - basic 2-of-3 DKG on Pallas
- `test_orchard_sign_2x3` - sign + aggregate with Pallas keys
- `test_orchard_key_import_2of3` - seed import + FROST + sign
- `test_orchard_reshare_2of2_to_2of3` - reshare preserves group key
- `test_orchard_key_import_mnemonic_seed` - known seed produces deterministic `ask`

### 1.5 DKG Ceremony Impact

**Zero additional network rounds.** Both DKGs run in parallel within the same 3-round
ceremony. Each party bundles Jubjub and Pallas messages together:

```
Round 1: party sends { jubjub_r1_package, pallas_r1_package }
Round 2: party sends { jubjub_r2_packages, pallas_r2_packages }
Round 3: local finalization of both KeyPackage<J> and KeyPackage<P>
```

Each party stores:
- `KeyPackage<J>` + `PublicKeyPackage<J>` (Sapling, existing)
- `KeyPackage<P>` + `PublicKeyPackage<P>` (Orchard, new)

Added computation per round is sub-second. Network latency dominates.

---

## Phase 2: Orchard Key Derivation + Addresses

### 2.1 Orchard Extras

Create `frozt-lib/src/orchard.rs` for Orchard-specific key derivation.

Orchard extras structure (96 bytes, same size as Sapling, different semantics):

```
Sapling extras:                    Orchard extras:
[0..32]   nsk  (Jubjub scalar)    [0..32]   nk   (Pallas base field element)
[32..64]  ovk  (32 bytes)         [32..64]  rivk (Pallas scalar)
[64..96]  dk   (32 bytes)         [64..96]  dk   (32 bytes)
```

Key differences from Sapling:
- **No `nsk`**: Orchard removed the nullifier spending key entirely
- **`nk` is a field element** (`pallas::Base`), not a curve point
- **`rivk`** (riveted internal viewing key) replaces `ovk` as the stored component.
  OVK is derived from the full viewing key, not stored directly
- **`dk`** is derived from the ZIP32 chain code, similar concept but different bytes

**`frozt_orchard_generate_extras(out_extras)`** - random 96-byte extras for seedless DKG

**`frozt_orchard_derive_extras_from_seed(seed, account_index, out_extras)`**

Derivation from the same 32-byte `sk` produced during spending key derivation:
```
nk   = pallas::Base::from_uniform_bytes(BLAKE2b-512("Zcash_ExpandSeed", sk || 0x07))
rivk = pallas::Scalar::from_uniform_bytes(BLAKE2b-512("Zcash_ExpandSeed", sk || 0x08))
dk   = from ZIP32 chain code derivation (last 32 bytes of extended key)
```

### 2.2 Full Viewing Key Construction

**`frozt_orchard_derive_fvk(pub_key_package, orchard_extras, out_fvk)`**

Construct Orchard `FullViewingKey` from FROST group key + extras:

```
fvk_bytes[0..32]   = ak (group verifying key from PublicKeyPackage<P>)
fvk_bytes[32..64]  = nk (from extras[0..32])
fvk_bytes[64..96]  = rivk (from extras[32..64])
```

Parse via `orchard::keys::FullViewingKey::from_bytes(&fvk_bytes)`.

Requires `orchard` crate with `unstable-frost` feature to expose
`FullViewingKey::from_bytes` and `SpendValidatingKey::from_bytes`.

### 2.3 Address Derivation

**`frozt_orchard_derive_address(pub_key_package, orchard_extras, out_address)`**

Orchard addresses are encoded as Unified Addresses (ZIP 316), not standalone bech32.

Steps:
1. Build FVK from group key + extras (as above)
2. Derive default address: `fvk.address_at(diversifier_index_0, Scope::External)`
3. Encode as Unified Address with Orchard-only receiver:
   - Receiver typecode: `0x03` (Orchard)
   - F4Jumble the payload
   - Bech32m encode with HRP `u` (mainnet) -> produces `u1...` address

For dual-pool Unified Addresses containing both Sapling and Orchard receivers,
construct a combined UA:
1. Get Orchard receiver (43 bytes) from Orchard FVK
2. Get Sapling receiver (43 bytes) from Sapling DFVK
3. Combine as `[(0x03, 43, orchard_addr), (0x02, 43, sapling_addr)]`
4. F4Jumble + Bech32m

**`frozt_orchard_derive_ivk(pub_key_package, orchard_extras, out_ivk)`**

Derive incoming viewing key for note decryption. Orchard IVK uses Sinsemilla-based
derivation (different from Sapling's Jubjub-based IVK).

### 2.4 Dependencies

Add to `frozt-lib/Cargo.toml`:
```toml
orchard = { version = "0.12", features = ["unstable-frost"] }
pasta_curves = "0.5"
```

The `pasta_curves` crate provides `pallas::Scalar`, `pallas::Point`, `pallas::Base`.
It may already be pulled transitively via `reddsa`, but should be declared explicitly.

---

## Phase 3: Orchard Transaction Building

**Priority: MEDIUM - blocked by `unstable-frost` API stabilization.**

### 3.1 Key Differences from Sapling Tx Building

| Aspect | Sapling (`tx.rs`) | Orchard |
|---|---|---|
| Proof system | Groth16 (192-byte proofs) | Halo 2 (~2KB proofs per action) |
| Param files | `sapling-spend.params` + `sapling-output.params` (~50MB) | None (transparent setup) |
| Spend/Output | Separate `SpendParts` + `OutputParts` | Unified `Action` (spend+output combined) |
| Build API | Manual per-spend/per-output proof gen | `orchard::Builder` constructs entire bundle |
| Binding sig | `redjubjub::Binding` (Jubjub) | `reddsa::orchard::Binding` (Pallas) |
| Value commitment | Jubjub Pedersen commitment | Pallas Pedersen commitment |
| Note commitment | Windowed Pedersen hash | Sinsemilla hash |

### 3.2 New Module: `frozt-lib/src/tx_orchard.rs`

#### `frozt_orchard_tx_build()`

```
Input:
  fvk_bytes: &[u8]           // 96-byte Orchard full viewing key
  note_data: &[u8]           // Orchard note (diversifier + value + rseed + rho)
  witness_data: &[u8]        // Orchard Merkle witness
  recipient_address: &str    // Unified address (u1...)
  recipient_amount: u64
  change_address: &str
  change_amount: u64
  target_height: u32

Output:
  out_tx_handle: Handle       // Opaque handle to OrchardTxBuildState
  out_sighash: [u8; 32]       // Transaction sighash
  out_alpha: [u8; 32]         // Randomizer for spend auth (from orchard::Builder)
```

Implementation approach:
1. Use `orchard::builder::Builder` to construct the bundle
2. Builder produces all actions, the proof, and the sighash in one call
3. Extract `alpha` via the `unstable-frost` getter on `SigningParts`
4. Return sighash for FROST signing and alpha for rerandomization

The chicken-and-egg problem (sighash depends on alpha, FROST needs sighash):
- The `orchard::Builder` generates alpha internally when constructing actions
- The sighash is computed after alpha is fixed
- FROST signs the sighash with the alpha applied as rerandomization
- This matches the existing Sapling flow where `alpha` is generated before sighash

#### `frozt_orchard_tx_finalize()`

```
Input:
  tx_handle: Handle           // From frozt_orchard_tx_build
  spend_auth_sig: &[u8]       // 64-byte RedPallas signature from FROST

Output:
  out_raw_tx: Vec<u8>         // Serialized v5 transaction
```

Steps:
1. Retrieve `OrchardTxBuildState` from handle
2. Insert FROST-produced spend auth signature into the action
3. Compute Pallas binding signature locally (from value commitment trapdoors)
4. Serialize v5 transaction with populated Orchard section and empty Sapling section

### 3.3 Sighash Computation

Update `compute_v5_sighash` to support Orchard digest:

Currently `hash_empty_orchard()` produces the empty digest. For Orchard transactions,
implement `hash_orchard()` with personalization `b"ZTxIdOrchardHash"` covering:
- Actions compact digest (`ZTxIdOrcActCHash`)
- Actions memos digest (`ZTxIdOrcActMHash`)
- Actions noncompact digest (`ZTxIdOrcActNHash`)
- Orchard flags, value balance, anchor

For mixed Sapling+Orchard transactions, both `hash_sapling()` and `hash_orchard()`
are non-empty and feed into the top-level sighash.

### 3.4 Transaction Serialization

The v5 format (ZIP 225) places the Orchard bundle after Sapling:

```
[Header]
[Transparent: empty]
[Sapling: populated OR empty depending on pool]
[Orchard section:]
  nActionsOrchard (compactsize)
  for each action:
    cv_net (32 bytes)
    nullifier (32 bytes)
    rk (32 bytes)
    cmx (32 bytes)
    ephemeralKey (32 bytes)
    encCiphertext (580 bytes)
    outCiphertext (80 bytes)
  flagsOrchard (1 byte)
  valueBalanceOrchard (int64)
  anchorOrchard (32 bytes)
  proofsOrchard (variable, 2720 + 2272 * nActions bytes)
  for each action:
    spendAuthSigOrchard (64 bytes)
  bindingSigOrchard (64 bytes)
```

---

## Phase 4: Orchard Note Scanning + Tree

### 4.1 Note Decryption

#### `frozt_orchard_try_decrypt_compact(ivk, cmx, ephemeral_key, ciphertext, out_value)`

Compact trial decryption for lightweight scanning:
- Uses `OrchardDomain` with `zcash_note_encryption` (same crate, different domain)
- `OrchardDomain` implements the `Domain` trait from `zcash_note_encryption`

#### `frozt_orchard_decrypt_note_full(ivk, cmx, ephemeral_key, enc_ciphertext, out_note_data)`

Full note decryption for wallet operations.

Orchard note data format (differs from Sapling's 51-byte format):
```
[0..11]   diversifier (11 bytes)
[11..19]  value (u64 LE)
[19..51]  rseed (32 bytes)
[51..83]  rho (32 bytes) -- Orchard-specific, used for nullifier derivation
```

### 4.2 Commitment Tree

#### `frozt-lib/src/tree_orchard.rs`

Orchard uses Sinsemilla hash for note commitments instead of Pedersen:
- Different `Node` type (Pallas base field element vs Jubjub)
- Same `incrementalmerkletree` crate, different hash function
- Tree depth is 32 (same as Sapling)

```rust
type OrchardNode = pallas::Base;  // Sinsemilla commitment
type OrchardTree = CommitmentTree<OrchardNode, NOTE_COMMITMENT_TREE_DEPTH>;
type OrchardWitness = IncrementalWitness<OrchardNode, NOTE_COMMITMENT_TREE_DEPTH>;
```

Functions:
- `frozt_orchard_tree_from_state(tree_state_hex, out_tree)`
- `frozt_orchard_tree_append(tree, cmx)`
- `frozt_orchard_tree_witness(tree, out_witness)`
- `frozt_orchard_witness_append(witness, cmx)`
- `frozt_orchard_witness_root(witness, out_anchor)`
- `frozt_orchard_witness_serialize(witness, out_data)`
- `frozt_orchard_witness_deserialize(data, out_witness)`

---

## Phase 5: Go + WASM Bindings

### 5.1 Go FFI (`go-frozt/frozt.go`)

Add Orchard equivalents for every existing function:

```go
// DKG
func OrchardDkgPart1(identifier, maxSigners, minSigners uint16) (Handle, []byte, error)
func OrchardDkgPart2(secret Handle, round1Packages []byte) (Handle, []byte, error)
func OrchardDkgPart3(secret Handle, round1Packages, round2Packages []byte) ([]byte, []byte, error)

// Signing
func OrchardSignCommit(keyPackage []byte) (Handle, []byte, error)
func OrchardSignNewPackage(message, commitmentsMap, pubKeyPackage []byte) ([]byte, []byte, error)
func OrchardSign(signingPackage []byte, nonces Handle, keyPackage, randomizer []byte) ([]byte, error)
func OrchardSignAggregate(signingPackage, sharesMap, pubKeyPackage, randomizer []byte) ([]byte, error)

// Key Import
func OrchardDeriveSpendingKeyFromSeed(seed []byte, accountIndex uint32) ([]byte, error)
func OrchardSpendingKeyToVerifyingKey(spendingKey []byte) ([]byte, error)
func OrchardKeyImportPart1(identifier, maxSigners, minSigners uint16, spendingKey []byte) (Handle, []byte, error)
func OrchardKeyImportPart3(secret Handle, round1Packages, round2Packages, expectedVK []byte) ([]byte, []byte, error)

// Reshare
func OrchardResharePart1(identifier, maxSigners, minSigners uint16, oldKeyPackage []byte, oldIdentifiers []uint16) (Handle, []byte, error)
func OrchardResharePart3(secret Handle, round1Packages, round2Packages, expectedVerifyingKey []byte) ([]byte, []byte, error)

// Key inspection
func OrchardKeyPackageIdentifier(keyPackage []byte) (uint16, error)
func OrchardPubKeyPackageVerifyingKey(pubKeyPackage []byte) ([]byte, error)

// Orchard-specific (Phase 2+)
func OrchardGenerateExtras() ([]byte, error)
func OrchardDeriveExtrasFromSeed(seed []byte, accountIndex uint32) ([]byte, error)
func OrchardDeriveAddress(pubKeyPackage, orchardExtras []byte) (string, error)
func OrchardDeriveFvk(pubKeyPackage, orchardExtras []byte) ([]byte, error)
func OrchardDeriveIvk(pubKeyPackage, orchardExtras []byte) ([]byte, error)
```

Update `go-frozt/includes/frozt-lib.h` to match `frozt-lib/include/frozt-lib.h`.

### 5.2 WASM Bindings (`frozt-wasm/`)

Create parallel WASM modules:
- `frozt-wasm/src/keygen_orchard.rs`
- `frozt-wasm/src/sign_orchard.rs`
- `frozt-wasm/src/key_import_orchard.rs`
- `frozt-wasm/src/reshare_orchard.rs`
- `frozt-wasm/src/keyshare_orchard.rs`
- `frozt-wasm/src/orchard.rs` (extras, addresses)

Each exports `#[wasm_bindgen]` functions with `frozt_orchard_` prefix.

Update `frozt-wasm/Cargo.toml` to add `pasta_curves` and (later) `orchard` dependencies.

---

## Phase 6: Orchestration + Dual-Pool Ceremony

### 6.1 Dual-DKG Ceremony (`go-frozt/orchestration/keygen.go`)

Modify the keygen orchestration to run both DKGs in the same 3-round ceremony:

```
Round 1:
  jubjub_secret, jubjub_r1_pkg = DkgPart1(id, n, t)
  pallas_secret, pallas_r1_pkg = OrchardDkgPart1(id, n, t)
  broadcast({ jubjub: jubjub_r1_pkg, pallas: pallas_r1_pkg })

Round 2:
  jubjub_secret2, jubjub_r2_pkgs = DkgPart2(jubjub_secret, jubjub_r1_all)
  pallas_secret2, pallas_r2_pkgs = OrchardDkgPart2(pallas_secret, pallas_r1_all)
  send_to_each({ jubjub: jubjub_r2_for_peer, pallas: pallas_r2_for_peer })

Round 3:
  jubjub_kp, jubjub_pkp = DkgPart3(jubjub_secret2, jubjub_r1_all, jubjub_r2_mine)
  pallas_kp, pallas_pkp = OrchardDkgPart3(pallas_secret2, pallas_r1_all, pallas_r2_mine)
  store(jubjub_kp, jubjub_pkp, pallas_kp, pallas_pkp)
```

The relay messages need a protocol version bump or envelope format to carry both payloads.

### 6.2 Dual Key Import Ceremony

Same pattern for seed-based key import:

```
seed -> DeriveSpendingKeyFromSeed(seed, account)          -> jubjub_ask
seed -> OrchardDeriveSpendingKeyFromSeed(seed, account)   -> pallas_ask

Round 1:
  Party with seed:   KeyImportPart1(id, n, t, jubjub_ask)
                     OrchardKeyImportPart1(id, n, t, pallas_ask)
  Other parties:     KeyImportPart1(id, n, t, nil)
                     OrchardKeyImportPart1(id, n, t, nil)

Round 2: (uses standard DkgPart2 / OrchardDkgPart2)

Round 3:
  KeyImportPart3(..., expected_jubjub_vk)
  OrchardKeyImportPart3(..., expected_pallas_vk)
```

### 6.3 Key Storage

Each party's vault stores:
```
Existing:
  sapling_key_package:     KeyPackage<JubjubBlake2b512>
  sapling_pub_key_package: PublicKeyPackage<JubjubBlake2b512>
  sapling_extras:          [u8; 96] (nsk + ovk + dk)

New:
  orchard_key_package:     KeyPackage<PallasBlake2b512>
  orchard_pub_key_package: PublicKeyPackage<PallasBlake2b512>
  orchard_extras:          [u8; 96] (nk + rivk + dk)
```

### 6.4 Dual-Pool Signing (Future: when Orchard tx building is ready)

For a transaction spending from both pools:
1. Build tx with both Sapling spends + Orchard actions
2. Compute single v5 sighash (commits to both pools)
3. FROST sign on Jubjub for each Sapling spend auth sig
4. FROST sign on Pallas for each Orchard action spend auth sig
5. Compute binding sigs locally per-pool (no FROST needed)

---

## Appendix: Cryptographic Reference

### Orchard `ask` Derivation from Seed

```
seed (64 bytes)
  |
  v
ZIP32 master: BLAKE2b-256(personalization="ZcashIP32Orchard", input=seed)
  |
  v
Hardened child derivation: domain byte 0x81
Path: m/32'/133'/account'
  |
  v
sk (32 opaque bytes)
  |
  v
ask = to_scalar(BLAKE2b-512("Zcash_ExpandSeed", sk || 0x06))
    = pallas::Scalar::from_uniform_bytes(&blake2b_output)
  |
  v
Even-Y check: if ([ask]*G).serialize()[31] & 0x80 != 0, then ask = -ask
  |
  v
ask (32-byte Pallas scalar) -- this is what FROST splits
```

### Orchard Extras Derivation from Seed

Using the same `sk` from the path above:
```
nk   = pallas::Base::from_uniform_bytes(BLAKE2b-512("Zcash_ExpandSeed", sk || 0x07))
rivk = pallas::Scalar::from_uniform_bytes(BLAKE2b-512("Zcash_ExpandSeed", sk || 0x08))
dk   = extracted from ZIP32 extended key chain code
```

### Orchard Full Viewing Key (96 bytes)

```
[0..32]   ak   = group verifying key from FROST PublicKeyPackage<P>
[32..64]  nk   = from extras[0..32]
[64..96]  rivk = from extras[32..64]
```

### Key Comparison Table

| Key | Sapling | Orchard |
|---|---|---|
| Spending key | `ask` (Jubjub scalar, from `expsk.ask`) | `ask` (Pallas scalar, from PRF with domain 0x06) |
| Spend validating key | `ak` (Jubjub point) | `ak` (Pallas point, must have even Y) |
| Nullifier private key | `nsk` (Jubjub scalar) | Does not exist |
| Nullifier key | `nk` (Jubjub point = nsk * G) | `nk` (Pallas base field element, from PRF domain 0x07) |
| Outgoing viewing key | `ovk` (32 bytes, stored directly) | Derived from FVK via `fvk.to_ovk(Scope)` |
| Riveted IVK | Does not exist | `rivk` (Pallas scalar, from PRF domain 0x08) |
| Diversifier key | `dk` (32 bytes) | `dk` (32 bytes, from ZIP32 chain) |

---

## Appendix: Dependency Changes

### `frozt-lib/Cargo.toml` additions

```toml
# Phase 1 (DKG/signing only - no new deps needed, pasta_curves is transitive via reddsa)
pasta_curves = "0.5"      # explicit dep for pallas::Scalar, pallas::Point, pallas::Base

# Phase 2+ (key derivation, addresses, tx building)
orchard = { version = "0.12", features = ["unstable-frost"] }
```

### `frozt-wasm/Cargo.toml` additions

```toml
pasta_curves = "0.5"
# Phase 2+:
orchard = { version = "0.12", features = ["unstable-frost"] }
```

### No changes needed

These existing dependencies work for both Sapling and Orchard:
- `frost-core = "2.2"` - curve-agnostic
- `frost-rerandomized = "2.2"` - curve-agnostic
- `reddsa` (pinned rev) - already has `frost::redpallas::PallasBlake2b512`
- `blake2b_simd = "1"` - used for PRF expand
- `incrementalmerkletree = "0.8"` - generic over node type
- `zcash_note_encryption = "0.4"` - generic over domain
- `zip32 = "0.2"` - has `hardened_only` module
- `bech32 = "0.11"` - for Unified Address encoding

### Dependencies that become Sapling-only (not needed for Orchard)

- `bellman = "0.14"` - Groth16 prover (Sapling only)
- `bls12_381 = "0.8"` - Sapling proof curve
- `sapling-crypto = "0.6"` - Sapling protocol
- `redjubjub = "0.8"` - Sapling signatures (reddsa handles both)
- `jubjub = "0.10"` - Sapling application curve

---

## Appendix: Blockers and Risks

### `unstable-frost` Feature Flag (Phases 2-3 Blocker)

The `orchard` crate's FROST APIs are behind `features = ["unstable-frost"]` and are
explicitly described as "temporary APIs exposed for development purposes" that
"will be replaced by type-safe FROST APIs once ZIP 312 key generation is specified."

Affected APIs:
- `SpendValidatingKey::from_bytes` / `to_bytes`
- `FullViewingKey` construction from FROST-generated group key
- `SigningParts` getter for alpha (randomizer)

**Impact**: Phases 2-3 may need rework when these APIs stabilize.
**Mitigation**: Phase 1 (DKG + signing) does NOT depend on the `orchard` crate at all.
It only uses `reddsa::frost::redpallas`, which is stable.

### ZIP 312 (FROST Key Generation Specification)

The formal specification for FROST key generation in Zcash (referenced as `zcash/zips#883`)
is still being written. Our key import approach (setting polynomial constant term to `ask`)
is compatible with the expected spec but may need adjustment.

### No Reference Implementation

No existing wallet combines FROST threshold signing with Orchard transaction construction.
There is an active Zcash grant application for "FROST Multi-Signature UI for Zcash Orchard"
but it has not been completed. Phases 3-4 are pioneering work.

### Orchard Proof Size

Halo 2 proofs are ~7KB for a 2-action tx vs ~576 bytes for Sapling. This increases
transaction size ~3.3x. Not a blocker but affects bandwidth and storage.

### Orchard Proving Time

Halo 2 proving is ~2x slower than Groth16 on native hardware, ~2.4x slower in WASM.
Offset by eliminating the ~50MB parameter file loading on cold start.
