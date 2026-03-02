use group::{ff::PrimeField, ff::Field, GroupEncoding};
use reddsa::frost::redjubjub::JubjubBlake2b512;
use sapling_crypto::{
    constants::PROOF_GENERATION_KEY_GENERATOR,
    keys::SaplingIvk,
    note::ExtractedNoteCommitment,
    note_encryption::{
        try_sapling_compact_note_decryption, try_sapling_note_decryption,
        CompactOutputDescription, PreparedIncomingViewingKey, SaplingDomain, Zip212Enforcement,
    },
    value::NoteValue,
    zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey},
    Diversifier, Note, Rseed,
};
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE};
use zip32::ChildIndex;

use zeroize::Zeroize;
use crate::{
    bytes::*,
    errors::*,
};

type J = JubjubBlake2b512;

const EXTRAS_LEN: usize = 96;

pub fn build_dfvk_raw(pkp_data: &[u8], extras: &[u8]) -> Result<[u8; 128], lib_error> {
    if extras.len() != EXTRAS_LEN {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    let pkp = frost_core::keys::PublicKeyPackage::<J>::deserialize(pkp_data)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
    let ak_serialized = pkp
        .verifying_key()
        .serialize()
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    let nsk_bytes: [u8; 32] = extras[..32].try_into().unwrap();
    let nsk: Option<jubjub::Fr> = jubjub::Fr::from_repr(nsk_bytes).into();
    let nsk = nsk.ok_or(lib_error::LIB_SAPLING_ERROR)?;
    let nk: jubjub::SubgroupPoint = PROOF_GENERATION_KEY_GENERATOR * nsk;

    let mut dfvk_raw = [0u8; 128];
    dfvk_raw[..32].copy_from_slice(ak_serialized.as_ref());
    dfvk_raw[32..64].copy_from_slice(&nk.to_bytes());
    dfvk_raw[64..96].copy_from_slice(&extras[32..64]);
    dfvk_raw[96..128].copy_from_slice(&extras[64..96]);

    Ok(dfvk_raw)
}

fn hardened_account_child(account_index: u32) -> Result<ChildIndex, lib_error> {
    if account_index >= (1u32 << 31) {
        return Err(lib_error::LIB_SAPLING_ERROR);
    }
    Ok(ChildIndex::hardened(account_index))
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_generate_extras(
    out_sapling_extras: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_sapling_extras.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut rng = rand::thread_rng();
        let mut extras = [0u8; EXTRAS_LEN];

        let nsk = jubjub::Fr::random(&mut rng);
        let mut nsk_repr = nsk.to_repr();
        extras[..32].copy_from_slice(&nsk_repr);
        nsk_repr.zeroize();

        rand::RngCore::fill_bytes(&mut rng, &mut extras[32..64]);
        rand::RngCore::fill_bytes(&mut rng, &mut extras[64..96]);

        *out = tss_buffer::from_vec(extras.to_vec());
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_derive_keys(
    pub_key_package: Option<&go_slice>,
    sapling_extras: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
    out_ivk: Option<&mut tss_buffer>,
    out_nk: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let extras_data = sapling_extras.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_addr = out_address.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_i = out_ivk.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_n = out_nk.ok_or(lib_error::LIB_NULL_PTR)?;

        let dfvk_raw = build_dfvk_raw(pkp_data.as_slice(), extras_data.as_slice())?;
        let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_raw)
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;

        let (_, addr) = dfvk.default_address();
        let hrp = bech32::Hrp::parse("zs")
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        let encoded = bech32::encode::<bech32::Bech32>(hrp, &addr.to_bytes())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let ivk = dfvk.fvk().vk.ivk();

        if extras_data.len() != EXTRAS_LEN {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }
        let nsk_bytes: [u8; 32] = extras_data.as_slice()[..32].try_into().unwrap();
        let nsk: Option<jubjub::Fr> = jubjub::Fr::from_repr(nsk_bytes).into();
        let nsk = nsk.ok_or(lib_error::LIB_SAPLING_ERROR)?;
        let nk: jubjub::SubgroupPoint = PROOF_GENERATION_KEY_GENERATOR * nsk;

        *out_addr = tss_buffer::from_vec(encoded.into_bytes());
        *out_i = tss_buffer::from_vec(ivk.0.to_repr().to_vec());
        *out_n = tss_buffer::from_vec(nk.to_bytes().to_vec());
        Ok(())
    })
}

pub(crate) fn derive_extras_from_seed(seed: &[u8], account_index: u32) -> Result<Vec<u8>, lib_error> {
    if seed.len() != 64 {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }

    let master = ExtendedSpendingKey::master(seed);
    let account = hardened_account_child(account_index)?;
    let path = [
        ChildIndex::hardened(32),
        ChildIndex::hardened(133),
        account,
    ];
    let child = ExtendedSpendingKey::from_path(&master, &path);

    let dfvk_bytes = child.to_diversifiable_full_viewing_key().to_bytes();

    let mut extras = [0u8; EXTRAS_LEN];
    let mut nsk_repr = child.expsk.nsk.to_repr();
    extras[..32].copy_from_slice(&nsk_repr);
    nsk_repr.zeroize();
    extras[32..64].copy_from_slice(&child.expsk.ovk.0);
    extras[64..96].copy_from_slice(&dfvk_bytes[96..128]);

    Ok(extras.to_vec())
}


#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_try_decrypt_compact(
    ivk: Option<&go_slice>,
    cmu: Option<&go_slice>,
    ephemeral_key: Option<&go_slice>,
    ciphertext: Option<&go_slice>,
    height: u64,
    out_value: Option<&mut u64>,
) -> lib_error {
    with_error_handler(|| {
        let ivk_data = ivk.ok_or(lib_error::LIB_NULL_PTR)?;
        let cmu_data = cmu.ok_or(lib_error::LIB_NULL_PTR)?;
        let epk_data = ephemeral_key.ok_or(lib_error::LIB_NULL_PTR)?;
        let ct_data = ciphertext.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_value.ok_or(lib_error::LIB_NULL_PTR)?;

        if ivk_data.len() != 32 || cmu_data.len() != 32 || epk_data.len() != 32 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }
        if ct_data.len() != COMPACT_NOTE_SIZE {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let ivk_bytes: [u8; 32] = ivk_data.as_slice()[..32].try_into().unwrap();
        let ivk_scalar: Option<jubjub::Fr> = jubjub::Fr::from_repr(ivk_bytes).into();
        let ivk_scalar = ivk_scalar.ok_or(lib_error::LIB_SAPLING_ERROR)?;
        let prepared = PreparedIncomingViewingKey::new(&SaplingIvk(ivk_scalar));

        let cmu_bytes: [u8; 32] = cmu_data.as_slice()[..32].try_into().unwrap();
        let extracted_cmu: Option<ExtractedNoteCommitment> =
            ExtractedNoteCommitment::from_bytes(&cmu_bytes).into();
        let extracted_cmu = extracted_cmu.ok_or(lib_error::LIB_SAPLING_ERROR)?;

        let epk_bytes: [u8; 32] = epk_data.as_slice()[..32].try_into().unwrap();

        let mut enc_ct = [0u8; COMPACT_NOTE_SIZE];
        enc_ct.copy_from_slice(&ct_data.as_slice()[..COMPACT_NOTE_SIZE]);

        let compact = CompactOutputDescription {
            ephemeral_key: EphemeralKeyBytes(epk_bytes),
            cmu: extracted_cmu,
            enc_ciphertext: enc_ct,
        };

        let result = try_sapling_compact_note_decryption(
            &prepared,
            &compact,
            zip212_for_height(height),
        );

        match result {
            Some((note, _addr)) => {
                *out = note.value().inner();
                Ok(())
            }
            None => Err(lib_error::LIB_SAPLING_ERROR),
        }
    })
}

struct FullOutput {
    cmu: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
}

impl ShieldedOutput<SaplingDomain, ENC_CIPHERTEXT_SIZE> for FullOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        self.ephemeral_key.clone()
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu.to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }
}

pub fn zip212_for_height(height: u64) -> Zip212Enforcement {
    if height >= 1_687_104 {
        Zip212Enforcement::On
    } else if height >= 903_000 {
        Zip212Enforcement::GracePeriod
    } else {
        Zip212Enforcement::Off
    }
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_decrypt_note_full(
    ivk: Option<&go_slice>,
    cmu: Option<&go_slice>,
    ephemeral_key: Option<&go_slice>,
    enc_ciphertext: Option<&go_slice>,
    height: u64,
    out_note_data: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let ivk_data = ivk.ok_or(lib_error::LIB_NULL_PTR)?;
        let cmu_data = cmu.ok_or(lib_error::LIB_NULL_PTR)?;
        let epk_data = ephemeral_key.ok_or(lib_error::LIB_NULL_PTR)?;
        let ct_data = enc_ciphertext.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_note_data.ok_or(lib_error::LIB_NULL_PTR)?;

        if ivk_data.len() != 32 || cmu_data.len() != 32 || epk_data.len() != 32 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }
        if ct_data.len() != ENC_CIPHERTEXT_SIZE {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let ivk_bytes: [u8; 32] = ivk_data.as_slice()[..32].try_into().unwrap();
        let ivk_scalar: Option<jubjub::Fr> = jubjub::Fr::from_repr(ivk_bytes).into();
        let ivk_scalar = ivk_scalar.ok_or(lib_error::LIB_SAPLING_ERROR)?;
        let prepared = PreparedIncomingViewingKey::new(&SaplingIvk(ivk_scalar));

        let cmu_bytes: [u8; 32] = cmu_data.as_slice()[..32].try_into().unwrap();
        let extracted_cmu: Option<ExtractedNoteCommitment> =
            ExtractedNoteCommitment::from_bytes(&cmu_bytes).into();
        let extracted_cmu = extracted_cmu.ok_or(lib_error::LIB_SAPLING_ERROR)?;

        let epk_bytes: [u8; 32] = epk_data.as_slice()[..32].try_into().unwrap();

        let mut enc_ct = [0u8; ENC_CIPHERTEXT_SIZE];
        enc_ct.copy_from_slice(&ct_data.as_slice()[..ENC_CIPHERTEXT_SIZE]);

        let output = FullOutput {
            cmu: extracted_cmu,
            ephemeral_key: EphemeralKeyBytes(epk_bytes),
            enc_ciphertext: enc_ct,
        };

        let zip212 = zip212_for_height(height);

        let result = try_sapling_note_decryption(&prepared, &output, zip212);

        match result {
            Some((note, addr, _memo)) => {
                let rseed_bytes = match note.rseed() {
                    sapling_crypto::Rseed::BeforeZip212(rcm) => rcm.to_repr(),
                    sapling_crypto::Rseed::AfterZip212(rseed) => *rseed,
                };
                let mut note_data = Vec::with_capacity(51);
                note_data.extend_from_slice(&addr.diversifier().0);
                note_data.extend_from_slice(&note.value().inner().to_le_bytes());
                note_data.extend_from_slice(&rseed_bytes);
                *out = tss_buffer::from_vec(note_data);
                Ok(())
            }
            None => Err(lib_error::LIB_SAPLING_ERROR),
        }
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_compute_nullifier(
    pkp_bytes: Option<&go_slice>,
    extras_bytes: Option<&go_slice>,
    note_data: Option<&go_slice>,
    position: u64,
    height: u64,
    out_nullifier: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pkp_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let extras_data = extras_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let nd = note_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_nullifier.ok_or(lib_error::LIB_NULL_PTR)?;

        if nd.len() != 51 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let dfvk_arr = build_dfvk_raw(pkp_data.as_slice(), extras_data.as_slice())?;
        let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_arr)
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;

        let nd_slice = nd.as_slice();
        let diversifier_bytes: [u8; 11] = nd_slice[..11].try_into().unwrap();
        let diversifier = Diversifier(diversifier_bytes);

        let value = u64::from_le_bytes(nd_slice[11..19].try_into().unwrap());

        let rseed_bytes: [u8; 32] = nd_slice[19..51].try_into().unwrap();
        let zip212 = zip212_for_height(height);
        let rseed = match zip212 {
            Zip212Enforcement::Off => {
                let rcm: Option<jubjub::Fr> = jubjub::Fr::from_repr(rseed_bytes).into();
                Rseed::BeforeZip212(rcm.ok_or(lib_error::LIB_SAPLING_ERROR)?)
            }
            _ => Rseed::AfterZip212(rseed_bytes),
        };

        let recipient = dfvk.fvk().vk.to_payment_address(diversifier)
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;

        let note = Note::from_parts(recipient, NoteValue::from_raw(value), rseed);

        let nf = note.nf(&dfvk.fvk().vk.nk, position);

        *out = tss_buffer::from_vec(nf.0.to_vec());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive_keys_helper(pkp: &[u8], extras: &[u8]) -> (String, Vec<u8>, Vec<u8>) {
        let pkp_slice = go_slice::from(pkp);
        let extras_slice = go_slice::from(extras);
        let mut addr_buf = tss_buffer::empty();
        let mut ivk_buf = tss_buffer::empty();
        let mut nk_buf = tss_buffer::empty();
        assert_eq!(
            frozt_sapling_derive_keys(
                Some(&pkp_slice),
                Some(&extras_slice),
                Some(&mut addr_buf),
                Some(&mut ivk_buf),
                Some(&mut nk_buf),
            ),
            lib_error::LIB_OK,
        );
        (
            String::from_utf8(addr_buf.into_vec()).unwrap(),
            ivk_buf.into_vec(),
            nk_buf.into_vec(),
        )
    }

    fn abandon_seed() -> Vec<u8> {
        hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap()
    }

    const ABANDON_ADDR: &str = "zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta";

    #[test]
    fn test_sapling_generate_and_derive() {
        let seed = abandon_seed();
        let import = crate::key_import::tests::run_key_import(3, 2, &seed, 0);
        let pkp = &import.results[0].1;
        assert_eq!(import.extras.len(), EXTRAS_LEN);

        let (addr, ivk, nk) = derive_keys_helper(pkp, &import.extras);
        assert_eq!(addr, ABANDON_ADDR);
        assert_eq!(ivk.len(), 32);
        assert_eq!(nk.len(), 32);
    }

    #[test]
    fn test_sapling_seedless_extras() {
        let mut extras_buf = tss_buffer::empty();
        assert_eq!(
            frozt_sapling_generate_extras(Some(&mut extras_buf)),
            lib_error::LIB_OK,
        );
        let extras = extras_buf.into_vec();
        assert_eq!(extras.len(), EXTRAS_LEN);

        let nsk_bytes: [u8; 32] = extras[..32].try_into().unwrap();
        let nsk: Option<jubjub::Fr> = jubjub::Fr::from_repr(nsk_bytes).into();
        assert!(nsk.is_some(), "nsk should be a valid scalar");
    }

    #[test]
    fn test_sapling_seedless_derive_keys() {
        let results = crate::keygen::tests::run_dkg(3, 2);
        assert!(!results.is_empty());
        let pkp = &results[0].1;

        let mut extras_buf = tss_buffer::empty();
        assert_eq!(
            frozt_sapling_generate_extras(Some(&mut extras_buf)),
            lib_error::LIB_OK,
        );
        let extras = extras_buf.into_vec();

        let (addr, ivk, nk) = derive_keys_helper(pkp, &extras);
        assert!(addr.starts_with("zs"), "address should start with zs: {}", addr);
        assert_eq!(ivk.len(), 32);
        assert_eq!(nk.len(), 32);
    }

    #[test]
    fn test_sapling_import_and_sign() {
        let seed = abandon_seed();
        let import = crate::key_import::tests::run_key_import(3, 2, &seed, 0);
        let pkp = &import.results[0].1;

        let (addr, _, _) = derive_keys_helper(pkp, &import.extras);
        assert_eq!(addr, ABANDON_ADDR);

        crate::sign::tests::run_sign(&import.results, &[0, 1]);
        crate::sign::tests::run_sign(&import.results, &[1, 2]);
    }

    #[test]
    fn test_sapling_derive_nk_via_keys() {
        let seed = abandon_seed();
        let import = crate::key_import::tests::run_key_import(3, 2, &seed, 0);
        let pkp = &import.results[0].1;

        let (_, _, nk) = derive_keys_helper(pkp, &import.extras);
        assert_eq!(nk.len(), 32);

        let nsk_bytes: [u8; 32] = import.extras[..32].try_into().unwrap();
        let nsk: jubjub::Fr = jubjub::Fr::from_repr(nsk_bytes).unwrap();
        let expected_nk = PROOF_GENERATION_KEY_GENERATOR * nsk;
        assert_eq!(nk, expected_nk.to_bytes());
    }
}
