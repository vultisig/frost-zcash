use frost_core::keys::PublicKeyPackage;
use group::GroupEncoding;
use sapling_crypto::{
    constants::PROOF_GENERATION_KEY_GENERATOR,
    keys::{Diversifier, ExpandedSpendingKey, FullViewingKey, NullifierDerivingKey},
};
use wasm_bindgen::prelude::*;

use crate::{to_js_err, J};

fn encode_bech32(hrp: &str, data: &[u8]) -> Result<String, JsError> {
    let hrp = bech32::Hrp::parse(hrp).map_err(to_js_err)?;
    bech32::encode::<bech32::Bech32>(hrp, data).map_err(to_js_err)
}

fn derive_sapling_ivk(
    ak_bytes: &[u8; 32],
) -> Result<sapling_crypto::keys::SaplingIvk, JsError> {
    let expsk = ExpandedSpendingKey::from_spending_key(ak_bytes);
    let nk = NullifierDerivingKey(PROOF_GENERATION_KEY_GENERATOR * expsk.nsk);

    let mut fvk_bytes = [0u8; 96];
    fvk_bytes[0..32].copy_from_slice(ak_bytes);
    fvk_bytes[32..64].copy_from_slice(&nk.0.to_bytes());
    fvk_bytes[64..96].copy_from_slice(&expsk.ovk.0);

    let fvk = FullViewingKey::read(&fvk_bytes[..]).map_err(to_js_err)?;
    Ok(fvk.vk.ivk())
}

#[wasm_bindgen]
pub fn frost_derive_z_address(pub_key_package: &[u8]) -> Result<String, JsError> {
    let pkp =
        PublicKeyPackage::<J>::deserialize(pub_key_package).map_err(to_js_err)?;
    let vk_bytes = pkp.verifying_key().serialize().map_err(to_js_err)?;

    let ak_bytes: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| JsError::new("verifying key is not 32 bytes"))?;

    let ivk = derive_sapling_ivk(&ak_bytes)?;

    let mut d_bytes = [0u8; 11];
    let mut payment_address = None;
    for i in 0u64..1_000_000 {
        d_bytes[..8].copy_from_slice(&i.to_le_bytes());
        let addr = ivk.to_payment_address(Diversifier(d_bytes));
        if addr.is_some() {
            payment_address = addr;
            break;
        }
    }
    let addr =
        payment_address.ok_or_else(|| JsError::new("no valid diversifier found"))?;

    encode_bech32("zs", &addr.to_bytes())
}

#[wasm_bindgen]
pub fn frost_pubkey_to_t_address(
    pub_key_package: &[u8],
) -> Result<String, JsError> {
    let pkp =
        PublicKeyPackage::<J>::deserialize(pub_key_package).map_err(to_js_err)?;
    let vk_bytes = pkp.verifying_key().serialize().map_err(to_js_err)?;

    use sha2::Digest;
    let sha_hash = sha2::Sha256::digest(&vk_bytes);
    let ripemd_hash = ripemd::Ripemd160::digest(&sha_hash);

    let mut payload = Vec::with_capacity(22);
    payload.push(0x1C);
    payload.push(0xB8);
    payload.extend_from_slice(&ripemd_hash);

    Ok(bs58::encode(&payload).with_check().into_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::tests::run_dkg_native;

    #[test]
    fn test_derive_z_address() {
        let results = run_dkg_native(3, 2);
        let addr = frost_derive_z_address(&results[0].1).unwrap();
        assert!(
            addr.starts_with("zs"),
            "z-address should start with 'zs': {}",
            addr
        );
    }

    #[test]
    fn test_derive_t_address() {
        let results = run_dkg_native(3, 2);
        let addr = frost_pubkey_to_t_address(&results[0].1).unwrap();
        assert!(
            addr.starts_with("t1"),
            "t-address should start with 't1': {}",
            addr
        );
    }
}
