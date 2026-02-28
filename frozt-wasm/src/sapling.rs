use ff::{Field, PrimeField};
use group::GroupEncoding;
use sapling_crypto::{
    constants::PROOF_GENERATION_KEY_GENERATOR,
    zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey},
};
use wasm_bindgen::prelude::*;
use zip32::ChildIndex;

use crate::{to_js_err, J};

const EXTRAS_LEN: usize = 96;

#[wasm_bindgen]
pub fn frozt_sapling_generate_extras() -> Result<Vec<u8>, JsError> {
    let mut rng = rand::thread_rng();
    let mut extras = vec![0u8; EXTRAS_LEN];

    let nsk = jubjub::Fr::random(&mut rng);
    extras[..32].copy_from_slice(&nsk.to_repr());

    rand::RngCore::fill_bytes(&mut rng, &mut extras[32..64]);
    rand::RngCore::fill_bytes(&mut rng, &mut extras[64..96]);

    Ok(extras)
}

#[wasm_bindgen]
pub fn frozt_sapling_derive_address(
    pub_key_package: &[u8],
    sapling_extras: &[u8],
) -> Result<String, JsError> {
    if sapling_extras.len() != EXTRAS_LEN {
        return Err(JsError::new("sapling extras must be 96 bytes"));
    }

    let pkp = frost_core::keys::PublicKeyPackage::<J>::deserialize(pub_key_package)
        .map_err(to_js_err)?;
    let ak_serialized = pkp.verifying_key().serialize().map_err(to_js_err)?;

    let nsk_bytes: [u8; 32] = sapling_extras[..32]
        .try_into()
        .map_err(|_| JsError::new("invalid nsk bytes"))?;
    let nsk: Option<jubjub::Fr> = jubjub::Fr::from_repr(nsk_bytes).into();
    let nsk = nsk.ok_or_else(|| JsError::new("invalid nsk scalar"))?;
    let nk: jubjub::SubgroupPoint = PROOF_GENERATION_KEY_GENERATOR * nsk;

    let mut dfvk_raw = [0u8; 128];
    dfvk_raw[..32].copy_from_slice(ak_serialized.as_ref());
    dfvk_raw[32..64].copy_from_slice(&nk.to_bytes());
    dfvk_raw[64..96].copy_from_slice(&sapling_extras[32..64]); // ovk
    dfvk_raw[96..128].copy_from_slice(&sapling_extras[64..96]); // dk

    let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_raw)
        .ok_or_else(|| JsError::new("invalid diversifiable full viewing key"))?;
    let (_, addr) = dfvk.default_address();

    let hrp = bech32::Hrp::parse("zs")
        .map_err(|e| JsError::new(&format!("bech32 hrp: {}", e)))?;
    let encoded = bech32::encode::<bech32::Bech32>(hrp, &addr.to_bytes())
        .map_err(|e| JsError::new(&format!("bech32 encode: {}", e)))?;

    Ok(encoded)
}

#[wasm_bindgen]
pub fn frozt_derive_sapling_extras_from_seed(
    seed: &[u8],
    account_index: u32,
) -> Result<Vec<u8>, JsError> {
    if seed.len() != 64 {
        return Err(JsError::new("seed must be 64 bytes"));
    }

    let master = ExtendedSpendingKey::master(seed);
    let path = [
        ChildIndex::hardened(32),
        ChildIndex::hardened(133),
        ChildIndex::hardened(account_index),
    ];
    let child = ExtendedSpendingKey::from_path(&master, &path);

    let dfvk_bytes = child.to_diversifiable_full_viewing_key().to_bytes();

    let mut extras = vec![0u8; EXTRAS_LEN];
    extras[..32].copy_from_slice(&child.expsk.nsk.to_repr());
    extras[32..64].copy_from_slice(&child.expsk.ovk.0);
    extras[64..96].copy_from_slice(&dfvk_bytes[96..128]); // dk

    Ok(extras)
}
