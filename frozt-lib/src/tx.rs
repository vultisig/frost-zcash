use std::io::{self, Write};

use blake2b_simd::Params as Blake2bParams;
use byteorder::{LittleEndian, WriteBytesExt};
use group::{ff::PrimeField, ff::Field};
use rand::thread_rng;
use sapling_crypto::{
    circuit::{OutputParameters, SpendParameters},
    keys::{FullViewingKey, OutgoingViewingKey},
    note_encryption::{sapling_note_encryption, SaplingDomain, Zip212Enforcement},
    prover::{OutputProver, SpendProver},
    value::{NoteValue, TrapdoorSum, ValueCommitTrapdoor, ValueCommitment},
    Diversifier, MerklePath, Node, Note, PaymentAddress, ProofGenerationKey, Rseed,
};
use sapling_crypto::bundle::GrothProofBytes;
use sapling_crypto::note::ExtractedNoteCommitment;
use zcash_address::unified::{Address as UnifiedAddress, Container, Encoding, Receiver};
use zcash_note_encryption::{Domain, EphemeralKeyBytes};
use zcash_protocol::consensus::NetworkType;

use zeroize::Zeroize;

use crate::{
    bytes::*,
    errors::*,
    handle::Handle,
    sapling::zip212_for_height,
    tree::{deserialize_witness, SaplingWitness},
};

const MAX_FEE_ZATOSHIS: u64 = 1_000_000;

lazy_static::lazy_static! {
    static ref SPEND_PARAMS: Result<SpendParameters, ()> = {
        let dir = default_params_dir();
        let path = std::path::Path::new(&dir).join("sapling-spend.params");
        let file = std::fs::File::open(&path).map_err(|_| ())?;
        SpendParameters::read(io::BufReader::new(file), true).map_err(|_| ())
    };
    static ref OUTPUT_PARAMS: Result<OutputParameters, ()> = {
        let dir = default_params_dir();
        let path = std::path::Path::new(&dir).join("sapling-output.params");
        let file = std::fs::File::open(&path).map_err(|_| ())?;
        OutputParameters::read(io::BufReader::new(file), true).map_err(|_| ())
    };
}

pub struct SpendParts {
    pub cv: ValueCommitment,
    pub anchor: bls12_381::Scalar,
    pub nullifier: sapling_crypto::Nullifier,
    pub rk: redjubjub::VerificationKey<redjubjub::SpendAuth>,
    pub zkproof: GrothProofBytes,
    pub rcv: ValueCommitTrapdoor,
}

pub struct OutputParts {
    pub cv: ValueCommitment,
    pub cmu: ExtractedNoteCommitment,
    pub ephemeral_key: EphemeralKeyBytes,
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
    pub zkproof: GrothProofBytes,
    pub rcv: ValueCommitTrapdoor,
}

pub struct TxBuildState {
    pub spends: Vec<SpendParts>,
    pub outputs: Vec<OutputParts>,
    pub value_balance: i64,
    pub consensus_branch_id: u32,
    pub expiry_height: u32,
    pub sighash: [u8; 32],
}

pub struct TxBuilder {
    fvk: FullViewingKey,
    pgk: ProofGenerationKey,
    ovk: OutgoingViewingKey,
    target_height: u32,
    zip212: Zip212Enforcement,
    spends: Vec<SpendParts>,
    outputs: Vec<OutputParts>,
    alphas: Vec<[u8; 32]>,
    total_input: u64,
    total_output: u64,
    finished: Option<TxBuildState>,
}

impl Drop for TxBuilder {
    fn drop(&mut self) {
        crate::zeroize_scalar(&mut self.pgk.nsk);
        for alpha in &mut self.alphas {
            alpha.zeroize();
        }
    }
}

pub fn build_tx_builder(
    pkp_data: &[u8],
    extras_data: &[u8],
    target_height: u32,
) -> Result<TxBuilder, lib_error> {
    let dfvk_raw = crate::sapling::build_dfvk_raw(pkp_data, extras_data)?;
    let dfvk = sapling_crypto::zip32::DiversifiableFullViewingKey::from_bytes(&dfvk_raw)
        .ok_or(lib_error::LIB_SAPLING_ERROR)?;
    let fvk = dfvk.fvk().clone();

    let mut nsk_arr: [u8; 32] = extras_data[..32].try_into().unwrap();
    let nsk: Option<jubjub::Fr> = jubjub::Fr::from_repr(nsk_arr).into();
    nsk_arr.zeroize();
    let nsk = nsk.ok_or(lib_error::LIB_SAPLING_ERROR)?;
    let pgk = ProofGenerationKey { ak: fvk.vk.ak.clone(), nsk };
    let ovk = fvk.ovk;
    let zip212 = zip212_for_height(target_height as u64);

    Ok(TxBuilder {
        fvk,
        pgk,
        ovk,
        target_height,
        zip212,
        spends: Vec::new(),
        outputs: Vec::new(),
        alphas: Vec::new(),
        total_input: 0,
        total_output: 0,
        finished: None,
    })
}

const _: () = {
    fn _assert_send<T: Send>() {}
    fn _check() {
        _assert_send::<SpendParts>();
        _assert_send::<OutputParts>();
        _assert_send::<TxBuildState>();
        _assert_send::<TxBuilder>();
    }
};

pub fn parse_payment_address(addr_str: &str) -> Result<PaymentAddress, lib_error> {
    if addr_str.starts_with("u1") {
        return parse_unified_address(addr_str);
    }

    let (hrp, data) = bech32::decode(addr_str)
        .map_err(|_| lib_error::LIB_SAPLING_ERROR)?;

    if hrp.as_str() != "zs" {
        return Err(lib_error::LIB_SAPLING_ERROR);
    }
    if data.len() != 43 {
        return Err(lib_error::LIB_SAPLING_ERROR);
    }

    let addr_bytes: [u8; 43] = data[..43].try_into().unwrap();
    PaymentAddress::from_bytes(&addr_bytes)
        .ok_or(lib_error::LIB_SAPLING_ERROR)
}

fn parse_unified_address(addr_str: &str) -> Result<PaymentAddress, lib_error> {
    let (network, ua) = UnifiedAddress::decode(addr_str)
        .map_err(|_| lib_error::LIB_SAPLING_ERROR)?;

    if network != NetworkType::Main {
        return Err(lib_error::LIB_SAPLING_ERROR);
    }

    for receiver in ua.items() {
        if let Receiver::Sapling(bytes) = receiver {
            return PaymentAddress::from_bytes(&bytes)
                .ok_or(lib_error::LIB_SAPLING_ERROR);
        }
    }

    Err(lib_error::LIB_SAPLING_ERROR)
}

pub fn branch_id_for_height(height: u32) -> u32 {
    if height >= 3_146_400 {
        0x4dec_4df0 // NU6.1
    } else if height >= 2_726_400 {
        0xc8e7_1055 // NU6
    } else {
        0xc2d6_d0b4 // NU5
    }
}

fn default_params_dir() -> String {
    if let Ok(dir) = std::env::var("ZCASH_PARAMS") {
        return dir;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{}/.zcash-params", home)
}

fn get_spend_params() -> Result<&'static SpendParameters, lib_error> {
    SPEND_PARAMS.as_ref().map_err(|_| lib_error::LIB_SAPLING_ERROR)
}

fn get_output_params() -> Result<&'static OutputParameters, lib_error> {
    OUTPUT_PARAMS.as_ref().map_err(|_| lib_error::LIB_SAPLING_ERROR)
}

pub fn make_spend(
    pgk: &ProofGenerationKey,
    fvk: &FullViewingKey,
    note: &Note,
    merkle_path: &MerklePath,
    alpha: jubjub::Scalar,
    spend_params: &SpendParameters,
) -> Result<SpendParts, lib_error> {
    let mut rng = thread_rng();
    let rcv = ValueCommitTrapdoor::random(&mut rng);
    let cv = ValueCommitment::derive(note.value(), rcv.clone());
    let rk = fvk.vk.ak.randomize(&alpha);
    let nullifier = note.nf(&fvk.vk.nk, u64::from(merkle_path.position()));

    let root_node = merkle_path.root(Node::from_cmu(&note.cmu()));
    let anchor_bytes = root_node.to_bytes();
    let anchor = bls12_381::Scalar::from_repr(anchor_bytes);
    let anchor: bls12_381::Scalar = Option::from(anchor)
        .ok_or(lib_error::LIB_SAPLING_ERROR)?;

    let circuit = SpendParameters::prepare_circuit(
        pgk.clone(), *note.recipient().diversifier(), *note.rseed(),
        note.value(), alpha, rcv.clone(), anchor, merkle_path.clone(),
    ).ok_or(lib_error::LIB_SAPLING_ERROR)?;

    let proof = spend_params.create_proof(circuit, &mut rng);
    let zkproof = SpendParameters::encode_proof(proof);

    Ok(SpendParts { cv, anchor, nullifier, rk, zkproof, rcv })
}

pub fn make_output(
    ovk: Option<OutgoingViewingKey>,
    to: PaymentAddress,
    value: NoteValue,
    memo: [u8; 512],
    zip212: Zip212Enforcement,
    output_params: &OutputParameters,
) -> Result<OutputParts, lib_error> {
    let mut rng = thread_rng();

    let rseed = match zip212 {
        Zip212Enforcement::On => {
            let mut b = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut b);
            Rseed::AfterZip212(b)
        }
        _ => Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
    };

    let note = Note::from_parts(to, value, rseed);
    let rcv = ValueCommitTrapdoor::random(&mut rng);
    let cv = ValueCommitment::derive(value, rcv.clone());
    let cmu = note.cmu();

    let ne = sapling_note_encryption(ovk, note.clone(), memo, &mut rng);

    let ephemeral_key = SaplingDomain::epk_bytes(ne.epk());
    let enc_ciphertext = ne.encrypt_note_plaintext();
    let out_ciphertext = ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng);

    let circuit = OutputParameters::prepare_circuit(
        ne.esk(), to, note.rcm(), value, rcv.clone(),
    );

    let proof = output_params.create_proof(circuit, &mut rng);
    let zkproof = OutputParameters::encode_proof(proof);

    Ok(OutputParts { cv, cmu, ephemeral_key, enc_ciphertext, out_ciphertext, zkproof, rcv })
}

pub fn compute_bsk(
    spend_rcvs: &[&ValueCommitTrapdoor],
    output_rcvs: &[&ValueCommitTrapdoor],
) -> redjubjub::SigningKey<redjubjub::Binding> {
    let spend_sum: TrapdoorSum = spend_rcvs.iter().copied().sum();
    let output_sum: TrapdoorSum = output_rcvs.iter().copied().sum();
    (spend_sum - output_sum).into_bsk()
}

pub fn compute_v5_sighash(
    spends: &[SpendParts],
    outputs: &[OutputParts],
    value_balance: i64,
    consensus_branch_id: u32,
    expiry_height: u32,
) -> [u8; 32] {
    let header_digest = hash_header(consensus_branch_id, expiry_height);
    let transparent_digest = hash_empty_transparent();
    let sapling_digest = hash_sapling(spends, outputs, value_balance);
    let orchard_digest = hash_empty_orchard();

    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(b"ZcashTxHash_");
    personal[12..].copy_from_slice(&consensus_branch_id.to_le_bytes());

    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(&personal)
        .to_state();
    h.update(&header_digest);
    h.update(&transparent_digest);
    h.update(&sapling_digest);
    h.update(&orchard_digest);
    h.finalize().as_bytes().try_into().unwrap()
}

fn hash_header(consensus_branch_id: u32, expiry_height: u32) -> [u8; 32] {
    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdHeadersHash")
        .to_state();
    let header: u32 = 5 | (1 << 31);
    h.update(&header.to_le_bytes());
    h.update(&0x26A7_270Au32.to_le_bytes());
    h.update(&consensus_branch_id.to_le_bytes());
    h.update(&0u32.to_le_bytes());
    h.update(&expiry_height.to_le_bytes());
    h.finalize().as_bytes().try_into().unwrap()
}

fn hash_empty_transparent() -> [u8; 32] {
    Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdTranspaHash")
        .to_state()
        .finalize()
        .as_bytes()
        .try_into()
        .unwrap()
}

fn hash_sapling(
    spends: &[SpendParts],
    outputs: &[OutputParts],
    value_balance: i64,
) -> [u8; 32] {
    if spends.is_empty() && outputs.is_empty() {
        return Blake2bParams::new()
            .hash_length(32)
            .personal(b"ZTxIdSaplingHash")
            .to_state()
            .finalize()
            .as_bytes()
            .try_into()
            .unwrap();
    }

    let spends_compact_digest = {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(b"ZTxIdSSpendCHash")
            .to_state();
        for spend in spends {
            h.update(&spend.nullifier.0);
        }
        h.finalize()
    };

    let spends_noncompact_digest = {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(b"ZTxIdSSpendNHash")
            .to_state();
        for spend in spends {
            h.update(&spend.cv.to_bytes());
            h.update(&spend.anchor.to_repr());
            let rk_bytes: [u8; 32] = spend.rk.clone().into();
            h.update(&rk_bytes);
        }
        h.finalize()
    };

    let spends_digest = {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(b"ZTxIdSSpendsHash")
            .to_state();
        h.update(spends_compact_digest.as_bytes());
        h.update(spends_noncompact_digest.as_bytes());
        h.finalize()
    };

    let outputs_compact_digest = {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(b"ZTxIdSOutC__Hash")
            .to_state();
        for output in outputs {
            h.update(&output.cmu.to_bytes());
            h.update(output.ephemeral_key.as_ref());
            h.update(&output.enc_ciphertext[..52]);
        }
        h.finalize()
    };

    let outputs_memos_digest = {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(b"ZTxIdSOutM__Hash")
            .to_state();
        for output in outputs {
            h.update(&output.enc_ciphertext[52..564]);
        }
        h.finalize()
    };

    let outputs_noncompact_digest = {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(b"ZTxIdSOutN__Hash")
            .to_state();
        for output in outputs {
            h.update(&output.cv.to_bytes());
            h.update(&output.enc_ciphertext[564..]);
            h.update(&output.out_ciphertext);
        }
        h.finalize()
    };

    let outputs_digest = {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(b"ZTxIdSOutputHash")
            .to_state();
        h.update(outputs_compact_digest.as_bytes());
        h.update(outputs_memos_digest.as_bytes());
        h.update(outputs_noncompact_digest.as_bytes());
        h.finalize()
    };

    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdSaplingHash")
        .to_state();
    h.update(spends_digest.as_bytes());
    h.update(outputs_digest.as_bytes());
    h.update(&value_balance.to_le_bytes());
    h.finalize().as_bytes().try_into().unwrap()
}

fn hash_empty_orchard() -> [u8; 32] {
    Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZTxIdOrchardHash")
        .to_state()
        .finalize()
        .as_bytes()
        .try_into()
        .unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_tx_builder_new(
    pkp_bytes: Option<&go_slice>,
    extras_bytes: Option<&go_slice>,
    target_height: u32,
    out_handle: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pkp_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let extras_data = extras_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_handle.ok_or(lib_error::LIB_NULL_PTR)?;

        let builder = build_tx_builder(pkp_data.as_slice(), extras_data.as_slice(), target_height)?;

        *out = Handle::allocate(builder)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_tx_builder_add_spend(
    builder_handle: Handle,
    note_data: Option<&go_slice>,
    witness_data: Option<&go_slice>,
    out_alpha: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let note_d = note_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let wit_data = witness_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_al = out_alpha.ok_or(lib_error::LIB_NULL_PTR)?;

        if note_d.len() != 51 { return Err(lib_error::LIB_INVALID_BUFFER_SIZE); }

        let mut builder = builder_handle.get::<TxBuilder>()?;

        let diversifier = Diversifier(note_d.as_slice()[..11].try_into().unwrap());
        let value_bytes: [u8; 8] = note_d.as_slice()[11..19].try_into().unwrap();
        let value = NoteValue::from_raw(u64::from_le_bytes(value_bytes));
        let rseed_bytes: [u8; 32] = note_d.as_slice()[19..51].try_into().unwrap();

        let rseed = match builder.zip212 {
            Zip212Enforcement::On => Rseed::AfterZip212(rseed_bytes),
            _ => {
                let rcm: Option<jubjub::Fr> = jubjub::Fr::from_repr(rseed_bytes).into();
                Rseed::BeforeZip212(rcm.ok_or(lib_error::LIB_SAPLING_ERROR)?)
            }
        };

        let pk_d = builder.fvk.vk.to_payment_address(diversifier)
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;
        let note = Note::from_parts(pk_d, value, rseed);

        let witness: SaplingWitness = deserialize_witness(wit_data.as_slice())?;
        let merkle_path = witness.path()
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;

        let spend_params = get_spend_params()?;

        let mut alpha = jubjub::Fr::random(&mut thread_rng());

        let spend = make_spend(&builder.pgk, &builder.fvk, &note, &merkle_path, alpha, spend_params)?;

        let mut alpha_repr = alpha.to_repr();
        crate::zeroize_scalar(&mut alpha);
        let alpha_bytes: [u8; 32] = alpha_repr;
        alpha_repr.zeroize();

        builder.total_input += value.inner();
        builder.spends.push(spend);
        builder.alphas.push(alpha_bytes);

        *out_al = tss_buffer::from_vec(alpha_bytes.to_vec());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_tx_builder_add_output(
    builder_handle: Handle,
    address: Option<&go_slice>,
    amount: u64,
) -> lib_error {
    with_error_handler(|| {
        let addr_data = address.ok_or(lib_error::LIB_NULL_PTR)?;

        let mut builder = builder_handle.get::<TxBuilder>()?;

        let addr_str = std::str::from_utf8(addr_data.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        let addr = parse_payment_address(addr_str)?;

        let output_params = get_output_params()?;
        let memo = [0u8; 512];

        let output = make_output(
            Some(builder.ovk),
            addr,
            NoteValue::from_raw(amount),
            memo,
            builder.zip212,
            output_params,
        )?;

        builder.total_output += amount;
        builder.outputs.push(output);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_tx_builder_build(
    builder_handle: Handle,
    out_sighash: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_sh = out_sighash.ok_or(lib_error::LIB_NULL_PTR)?;

        let mut builder = builder_handle.get::<TxBuilder>()?;

        if builder.spends.is_empty() {
            return Err(lib_error::LIB_SAPLING_ERROR);
        }

        if builder.total_output > builder.total_input {
            return Err(lib_error::LIB_SAPLING_ERROR);
        }
        let fee = builder.total_input - builder.total_output;
        if fee > MAX_FEE_ZATOSHIS {
            return Err(lib_error::LIB_SAPLING_ERROR);
        }

        let spends = std::mem::take(&mut builder.spends);
        let outputs = std::mem::take(&mut builder.outputs);

        let value_balance = fee as i64;
        let consensus_branch_id = branch_id_for_height(builder.target_height);
        let expiry_height = builder.target_height + 100;

        let sighash = compute_v5_sighash(
            &spends, &outputs,
            value_balance, consensus_branch_id, expiry_height,
        );

        let state = TxBuildState {
            spends,
            outputs,
            value_balance,
            consensus_branch_id,
            expiry_height,
            sighash,
        };

        builder.finished = Some(state);
        *out_sh = tss_buffer::from_vec(sighash.to_vec());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_tx_builder_complete(
    builder_handle: Handle,
    spend_auth_sigs: Option<&go_slice>,
    out_raw_tx: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sig_data = spend_auth_sigs.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_raw_tx.ok_or(lib_error::LIB_NULL_PTR)?;

        let mut builder: TxBuilder = builder_handle.take()?;
        let state = builder.finished.take()
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;

        let n_spends = state.spends.len();
        if sig_data.len() != 64 * n_spends {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let mut spend_sigs = Vec::with_capacity(n_spends);
        for i in 0..n_spends {
            let sig_bytes: [u8; 64] = sig_data.as_slice()[i*64..(i+1)*64].try_into().unwrap();
            spend_sigs.push(redjubjub::Signature::<redjubjub::SpendAuth>::from(sig_bytes));
        }

        let spend_rcvs: Vec<&ValueCommitTrapdoor> = state.spends.iter().map(|s| &s.rcv).collect();
        let output_rcvs: Vec<&ValueCommitTrapdoor> = state.outputs.iter().map(|o| &o.rcv).collect();
        let bsk = compute_bsk(&spend_rcvs, &output_rcvs);

        let mut rng = thread_rng();
        let binding_sig = bsk.sign(&mut rng, &state.sighash);

        let raw_tx = serialize_v5_tx(
            &state.spends, &state.outputs, state.value_balance,
            &spend_sigs, &binding_sig,
            state.consensus_branch_id, state.expiry_height,
        )?;

        *out = tss_buffer::from_vec(raw_tx);
        Ok(())
    })
}

pub fn serialize_v5_tx(
    spends: &[SpendParts],
    outputs: &[OutputParts],
    value_balance: i64,
    spend_auth_sigs: &[redjubjub::Signature<redjubjub::SpendAuth>],
    binding_sig: &redjubjub::Signature<redjubjub::Binding>,
    consensus_branch_id: u32,
    expiry_height: u32,
) -> Result<Vec<u8>, lib_error> {
    if spend_auth_sigs.len() != spends.len() {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    let mut tx = Vec::with_capacity(4096);
    let w = |_e: io::Error| lib_error::LIB_SERIALIZATION_ERROR;

    tx.write_u32::<LittleEndian>(5 | (1 << 31)).map_err(w)?;
    tx.write_u32::<LittleEndian>(0x26A7_270A).map_err(w)?;
    tx.write_u32::<LittleEndian>(consensus_branch_id).map_err(w)?;
    tx.write_u32::<LittleEndian>(0).map_err(w)?;
    tx.write_u32::<LittleEndian>(expiry_height).map_err(w)?;

    write_compactsize(&mut tx, 0)?;
    write_compactsize(&mut tx, 0)?;

    write_compactsize(&mut tx, spends.len() as u64)?;

    for spend in spends {
        tx.write_all(&spend.cv.to_bytes()).map_err(w)?;
        tx.write_all(&spend.nullifier.0).map_err(w)?;
        let rk_bytes: [u8; 32] = spend.rk.clone().into();
        tx.write_all(&rk_bytes).map_err(w)?;
    }

    write_compactsize(&mut tx, outputs.len() as u64)?;

    for output in outputs {
        tx.write_all(&output.cv.to_bytes()).map_err(w)?;
        tx.write_all(&output.cmu.to_bytes()).map_err(w)?;
        tx.write_all(output.ephemeral_key.as_ref()).map_err(w)?;
        tx.write_all(&output.enc_ciphertext).map_err(w)?;
        tx.write_all(&output.out_ciphertext).map_err(w)?;
    }

    if !spends.is_empty() || !outputs.is_empty() {
        tx.write_i64::<LittleEndian>(value_balance).map_err(w)?;
    }

    if !spends.is_empty() {
        tx.write_all(&spends[0].anchor.to_repr()).map_err(w)?;
    }

    for spend in spends {
        tx.write_all(&spend.zkproof).map_err(w)?;
    }

    for sig in spend_auth_sigs {
        let sig_bytes: [u8; 64] = (*sig).into();
        tx.write_all(&sig_bytes).map_err(w)?;
    }

    for output in outputs {
        tx.write_all(&output.zkproof).map_err(w)?;
    }

    if !spends.is_empty() || !outputs.is_empty() {
        let bsig_bytes: [u8; 64] = (*binding_sig).into();
        tx.write_all(&bsig_bytes).map_err(w)?;
    }

    write_compactsize(&mut tx, 0)?; // nActionsOrchard

    Ok(tx)
}

fn write_compactsize(w: &mut Vec<u8>, n: u64) -> Result<(), lib_error> {
    if n < 253 {
        w.push(n as u8);
    } else if n <= 0xFFFF {
        w.push(253);
        w.write_u16::<LittleEndian>(n as u16).map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
    } else if n <= 0xFFFF_FFFF {
        w.push(254);
        w.write_u32::<LittleEndian>(n as u32).map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
    } else {
        w.push(255);
        w.write_u64::<LittleEndian>(n).map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{go_slice, tss_buffer};
    use crate::errors::lib_error;
    use crate::handle::Handle;
    use crate::key_import;

    struct TestKeyMaterial {
        pkp: Vec<u8>,
        extras: Vec<u8>,
    }

    const ABANDON_ADDR: &str = "zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta";

    fn setup_key_material() -> TestKeyMaterial {
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap();
        let import = key_import::tests::run_key_import(3, 2, &seed, 0);
        let pkp = import.results[0].1.clone();
        let extras = import.extras;

        TestKeyMaterial { pkp, extras }
    }

    #[test]
    fn test_parse_payment_address_valid() {
        let addr = "zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta";
        let result = parse_payment_address(addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_payment_address_invalid_hrp() {
        let result = parse_payment_address("zt1invalidprefix");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_payment_address_invalid_bech32() {
        let result = parse_payment_address("zs1notvalidbech32data!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unified_address_with_sapling() {
        let zs_addr = "zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta";
        let zs_pa = parse_payment_address(zs_addr).unwrap();

        let sapling_receiver = Receiver::Sapling(zs_pa.to_bytes());
        let ua = UnifiedAddress::try_from_items(vec![sapling_receiver]).unwrap();
        let ua_str = ua.encode(&NetworkType::Main);
        assert!(ua_str.starts_with("u1"));

        let ua_pa = parse_payment_address(&ua_str).unwrap();
        assert_eq!(zs_pa.to_bytes(), ua_pa.to_bytes());
    }

    #[test]
    fn test_parse_unified_address_no_sapling_receiver() {
        let unknown_receiver = Receiver::Unknown { typecode: 0xFF, data: vec![0u8; 32] };
        let ua = UnifiedAddress::try_from_items(vec![unknown_receiver]).unwrap();
        let ua_str = ua.encode(&NetworkType::Main);
        let result = parse_payment_address(&ua_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_branch_id_for_height() {
        assert_eq!(branch_id_for_height(2_000_000), 0xc2d6_d0b4, "NU5");
        assert_eq!(branch_id_for_height(2_726_400), 0xc8e7_1055, "NU6");
        assert_eq!(branch_id_for_height(3_000_000), 0xc8e7_1055, "NU6");
        assert_eq!(branch_id_for_height(3_146_400), 0x4dec_4df0, "NU6.1");
        assert_eq!(branch_id_for_height(4_000_000), 0x4dec_4df0, "NU6.1");
    }

    #[test]
    fn test_write_compactsize_values() {
        let mut buf = Vec::new();
        write_compactsize(&mut buf, 0).unwrap();
        assert_eq!(buf, vec![0]);

        buf.clear();
        write_compactsize(&mut buf, 252).unwrap();
        assert_eq!(buf, vec![252]);

        buf.clear();
        write_compactsize(&mut buf, 253).unwrap();
        assert_eq!(buf.len(), 3);
        assert_eq!(buf[0], 253);

        buf.clear();
        write_compactsize(&mut buf, 0x10000).unwrap();
        assert_eq!(buf.len(), 5);
        assert_eq!(buf[0], 254);
    }

    #[test]
    fn test_sighash_deterministic() {
        let sighash1 = compute_v5_sighash(&[], &[], 0, 0xc2d6_d0b4, 100);
        let sighash2 = compute_v5_sighash(&[], &[], 0, 0xc2d6_d0b4, 100);
        assert_eq!(sighash1, sighash2, "empty sighash should be deterministic");
        assert_ne!(sighash1, [0u8; 32], "sighash should not be all zeros");
    }

    #[test]
    fn test_sighash_varies_with_branch_id() {
        let sh1 = compute_v5_sighash(&[], &[], 0, 0xc2d6_d0b4, 100);
        let sh2 = compute_v5_sighash(&[], &[], 0, 0xc8e7_1055, 100);
        assert_ne!(sh1, sh2, "different branch IDs should produce different sighashes");
    }

    #[test]
    fn test_serialize_empty_tx() {
        let binding_sig = redjubjub::Signature::<redjubjub::Binding>::from([0u8; 64]);
        let raw_tx = serialize_v5_tx(
            &[], &[], 0, &[], &binding_sig, 0xc2d6_d0b4, 100,
        ).unwrap();

        assert!(raw_tx.len() >= 20, "empty tx should have header");
        let header = u32::from_le_bytes(raw_tx[0..4].try_into().unwrap());
        assert_eq!(header, 5 | (1 << 31), "v5 tx header");
        let version_group = u32::from_le_bytes(raw_tx[4..8].try_into().unwrap());
        assert_eq!(version_group, 0x26A7_270A);
        let branch = u32::from_le_bytes(raw_tx[8..12].try_into().unwrap());
        assert_eq!(branch, 0xc2d6_d0b4);
        let expiry = u32::from_le_bytes(raw_tx[16..20].try_into().unwrap());
        assert_eq!(expiry, 100);
    }

    #[test]
    fn test_serialize_tx_sig_count_mismatch() {
        let binding_sig = redjubjub::Signature::<redjubjub::Binding>::from([0u8; 64]);
        let result = serialize_v5_tx(
            &[], &[], 0, &[redjubjub::Signature::<redjubjub::SpendAuth>::from([0u8; 64])],
            &binding_sig, 0xc2d6_d0b4, 100,
        );
        assert!(result.is_err(), "sig count mismatch should fail");
    }

    #[test]
    fn test_tx_builder_new_and_build_no_spends() {
        let keys = setup_key_material();

        let pkp_slice = go_slice::from(keys.pkp.as_slice());
        let extras_slice = go_slice::from(keys.extras.as_slice());

        let mut builder_handle = Handle::null();
        assert_eq!(
            frozt_tx_builder_new(
                Some(&pkp_slice), Some(&extras_slice), 2_800_000,
                Some(&mut builder_handle),
            ),
            lib_error::LIB_OK,
        );
        assert_ne!(builder_handle, Handle::null());

        let mut sighash_buf = tss_buffer::empty();
        let result = frozt_tx_builder_build(
            builder_handle,
            Some(&mut sighash_buf),
        );
        assert_eq!(result, lib_error::LIB_SAPLING_ERROR, "build with no spends should fail");

        Handle::free(builder_handle).unwrap();
    }

    #[test]
    fn test_tx_builder_invalid_extras_size() {
        let keys = setup_key_material();
        let bad_extras = vec![0u8; 32];

        let pkp_slice = go_slice::from(keys.pkp.as_slice());
        let extras_slice = go_slice::from(bad_extras.as_slice());

        let mut builder_handle = Handle::null();
        let result = frozt_tx_builder_new(
            Some(&pkp_slice), Some(&extras_slice), 2_800_000,
            Some(&mut builder_handle),
        );
        assert_eq!(result, lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    #[test]
    fn test_tx_builder_add_output() {
        let keys = setup_key_material();

        let pkp_slice = go_slice::from(keys.pkp.as_slice());
        let extras_slice = go_slice::from(keys.extras.as_slice());

        let mut builder_handle = Handle::null();
        assert_eq!(
            frozt_tx_builder_new(
                Some(&pkp_slice), Some(&extras_slice), 2_800_000,
                Some(&mut builder_handle),
            ),
            lib_error::LIB_OK,
        );

        let addr = "zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta";
        let addr_slice = go_slice::from(addr.as_bytes());
        let result = frozt_tx_builder_add_output(builder_handle, Some(&addr_slice), 100_000);
        assert_eq!(result, lib_error::LIB_OK);

        Handle::free(builder_handle).unwrap();
    }
}
