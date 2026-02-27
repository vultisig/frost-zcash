use group::GroupEncoding;
use sapling_crypto::{
    constants::PROOF_GENERATION_KEY_GENERATOR,
    keys::{Diversifier, ExpandedSpendingKey, FullViewingKey, NullifierDerivingKey},
};

use crate::{
    bytes::*,
    errors::*,
};

fn encode_bech32(hrp: &str, data: &[u8]) -> Result<String, lib_error> {
    let hrp = bech32::Hrp::parse(hrp).map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
    bech32::encode::<bech32::Bech32>(hrp, data)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)
}

fn derive_sapling_ivk(ak_bytes: &[u8; 32]) -> Result<sapling_crypto::keys::SaplingIvk, lib_error> {
    let expsk = ExpandedSpendingKey::from_spending_key(ak_bytes);
    let nk = NullifierDerivingKey(PROOF_GENERATION_KEY_GENERATOR * expsk.nsk);

    let mut fvk_bytes = [0u8; 96];
    fvk_bytes[0..32].copy_from_slice(ak_bytes);
    fvk_bytes[32..64].copy_from_slice(&nk.0.to_bytes());
    fvk_bytes[64..96].copy_from_slice(&expsk.ovk.0);

    let fvk = FullViewingKey::read(&fvk_bytes[..])
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    Ok(fvk.vk.ivk())
}

#[no_mangle]
pub extern "C" fn frost_derive_z_address(
    pub_key_package: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let pkp = frost_core::keys::PublicKeyPackage::<
            reddsa::frost::redjubjub::JubjubBlake2b512,
        >::deserialize(pkp_data.as_slice())
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let vk_bytes = pkp.verifying_key()
            .serialize()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let ak_bytes: [u8; 32] = vk_bytes
            .try_into()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

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
        let addr = payment_address.ok_or(lib_error::LIB_SIGNING_ERROR)?;

        let encoded = encode_bech32("zs", &addr.to_bytes())?;

        *out = tss_buffer::from_vec(encoded.into_bytes());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frost_derive_t_address(
    pubkey_hash: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let hash_data = pubkey_hash.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let hash_bytes = hash_data.as_slice();
        if hash_bytes.len() != 20 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let mut payload = Vec::with_capacity(22);
        payload.push(0x1C);
        payload.push(0xB8);
        payload.extend_from_slice(hash_bytes);

        let encoded = bs58::encode(&payload).with_check().into_string();

        *out = tss_buffer::from_vec(encoded.into_bytes());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frost_pubkey_to_t_address(
    pub_key_package: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        let pkp = frost_core::keys::PublicKeyPackage::<
            reddsa::frost::redjubjub::JubjubBlake2b512,
        >::deserialize(pkp_data.as_slice())
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let vk_bytes = pkp.verifying_key()
            .serialize()
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        use sha2::Digest;
        let sha_hash = sha2::Sha256::digest(&vk_bytes);
        let ripemd_hash = ripemd::Ripemd160::digest(&sha_hash);

        let mut payload = Vec::with_capacity(22);
        payload.push(0x1C);
        payload.push(0xB8);
        payload.extend_from_slice(&ripemd_hash);

        let encoded = bs58::encode(&payload).with_check().into_string();

        *out = tss_buffer::from_vec(encoded.into_bytes());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::tests::run_dkg;

    #[test]
    fn test_derive_z_address() {
        let results = run_dkg(3, 2);
        let pkp_slice = go_slice::from(results[0].1.as_slice());

        let mut addr = tss_buffer::empty();
        assert_eq!(
            frost_derive_z_address(Some(&pkp_slice), Some(&mut addr)),
            lib_error::LIB_OK,
        );

        let addr_str = String::from_utf8(addr.into_vec()).unwrap();
        assert!(addr_str.starts_with("zs"), "z-address should start with 'zs': {}", addr_str);
        println!("z-address: {}", addr_str);
    }

    #[test]
    fn test_derive_t_address() {
        let results = run_dkg(3, 2);
        let pkp_slice = go_slice::from(results[0].1.as_slice());

        let mut addr = tss_buffer::empty();
        assert_eq!(
            frost_pubkey_to_t_address(Some(&pkp_slice), Some(&mut addr)),
            lib_error::LIB_OK,
        );

        let addr_str = String::from_utf8(addr.into_vec()).unwrap();
        assert!(addr_str.starts_with("t1"), "t-address should start with 't1': {}", addr_str);
        println!("t-address: {}", addr_str);
    }
}
