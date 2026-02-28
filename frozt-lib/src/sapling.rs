use group::{ff::PrimeField, ff::Field, GroupEncoding};
use reddsa::frost::redjubjub::JubjubBlake2b512;
use sapling_crypto::{
    constants::PROOF_GENERATION_KEY_GENERATOR,
    zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey},
};
use zip32::ChildIndex;

use crate::{
    bytes::*,
    errors::*,
};

type J = JubjubBlake2b512;

const EXTRAS_LEN: usize = 96;

fn hardened_account_child(account_index: u32) -> Result<ChildIndex, lib_error> {
    if account_index >= (1u32 << 31) {
        return Err(lib_error::LIB_SAPLING_ERROR);
    }
    Ok(ChildIndex::hardened(account_index))
}

#[no_mangle]
pub extern "C" fn frozt_sapling_generate_extras(
    out_sapling_extras: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_sapling_extras.ok_or(lib_error::LIB_NULL_PTR)?;
        let mut rng = rand::thread_rng();
        let mut extras = [0u8; EXTRAS_LEN];

        let nsk = jubjub::Fr::random(&mut rng);
        extras[..32].copy_from_slice(&nsk.to_repr());

        rand::RngCore::fill_bytes(&mut rng, &mut extras[32..64]);
        rand::RngCore::fill_bytes(&mut rng, &mut extras[64..96]);

        *out = tss_buffer::from_vec(extras.to_vec());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frozt_sapling_derive_address(
    pub_key_package: Option<&go_slice>,
    sapling_extras: Option<&go_slice>,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let extras_data = sapling_extras.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        if extras_data.len() != EXTRAS_LEN {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let extras = extras_data.as_slice();

        let pkp = frost_core::keys::PublicKeyPackage::<J>::deserialize(pkp_data.as_slice())
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
        dfvk_raw[64..96].copy_from_slice(&extras[32..64]); // ovk
        dfvk_raw[96..128].copy_from_slice(&extras[64..96]); // dk

        let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_raw)
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;
        let (_, addr) = dfvk.default_address();

        let hrp = bech32::Hrp::parse("zs")
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        let encoded = bech32::encode::<bech32::Bech32>(hrp, &addr.to_bytes())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        *out = tss_buffer::from_vec(encoded.into_bytes());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frozt_derive_sapling_extras_from_seed(
    seed: Option<&go_slice>,
    account_index: u32,
    out_sapling_extras: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let seed_data = seed.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_sapling_extras.ok_or(lib_error::LIB_NULL_PTR)?;

        if seed_data.len() != 64 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let master = ExtendedSpendingKey::master(seed_data.as_slice());
        let account = hardened_account_child(account_index)?;
        let path = [
            ChildIndex::hardened(32),
            ChildIndex::hardened(133),
            account,
        ];
        let child = ExtendedSpendingKey::from_path(&master, &path);

        let dfvk_bytes = child.to_diversifiable_full_viewing_key().to_bytes();

        let mut extras = [0u8; EXTRAS_LEN];
        extras[..32].copy_from_slice(&child.expsk.nsk.to_repr());
        extras[32..64].copy_from_slice(&child.expsk.ovk.0);
        extras[64..96].copy_from_slice(&dfvk_bytes[96..128]); // dk

        *out = tss_buffer::from_vec(extras.to_vec());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_import;

    #[test]
    fn test_sapling_generate_and_derive() {
        let seed = [0xABu8; 64];
        let seed_slice = go_slice::from(seed.as_slice());

        let mut sk_buf = tss_buffer::empty();
        assert_eq!(
            key_import::frozt_derive_spending_key_from_seed(
                Some(&seed_slice),
                0,
                Some(&mut sk_buf),
            ),
            lib_error::LIB_OK,
        );
        let sk = sk_buf.into_vec();

        let sk_slice = go_slice::from(sk.as_slice());
        let mut vk_buf = tss_buffer::empty();
        assert_eq!(
            key_import::frozt_spending_key_to_verifying_key(Some(&sk_slice), Some(&mut vk_buf)),
            lib_error::LIB_OK,
        );
        let vk = vk_buf.into_vec();

        let results =
            crate::key_import::tests::run_key_import(3, 2, &sk, &vk);
        let pkp = &results[0].1;

        let mut extras_buf = tss_buffer::empty();
        assert_eq!(
            frozt_derive_sapling_extras_from_seed(Some(&seed_slice), 0, Some(&mut extras_buf)),
            lib_error::LIB_OK,
        );
        let extras = extras_buf.into_vec();
        assert_eq!(extras.len(), EXTRAS_LEN);

        let pkp_slice = go_slice::from(pkp.as_slice());
        let extras_slice = go_slice::from(extras.as_slice());
        let mut addr_buf = tss_buffer::empty();
        assert_eq!(
            frozt_sapling_derive_address(
                Some(&pkp_slice),
                Some(&extras_slice),
                Some(&mut addr_buf),
            ),
            lib_error::LIB_OK,
        );
        let addr = String::from_utf8(addr_buf.into_vec()).unwrap();
        let expected = "zs1r53tpdj9zzr35du6lp82c3e75gfp9wvdmgg77a50s4clcncvck2al4hs66yfpterjzzwgctej6s";
        assert_eq!(addr, expected, "z-address should match wallet for 0xAB seed");
    }

    #[test]
    fn test_sapling_extras_from_seed_matches_known_address() {
        let seed = hex::decode(
            "c829196323d2eea891b2b6a01e0f10f31645a339e0b1ab0c1f3184d6ac58589a\
             2fdab5c19437877ba33887541a27436eb287393dea0265a3681da5e6f5853627"
        ).unwrap();

        let seed_slice = go_slice::from(seed.as_slice());
        let mut sk_buf = tss_buffer::empty();
        assert_eq!(
            key_import::frozt_derive_spending_key_from_seed(Some(&seed_slice), 0, Some(&mut sk_buf)),
            lib_error::LIB_OK,
        );
        let sk = sk_buf.into_vec();

        let sk_slice = go_slice::from(sk.as_slice());
        let mut vk_buf = tss_buffer::empty();
        assert_eq!(
            key_import::frozt_spending_key_to_verifying_key(Some(&sk_slice), Some(&mut vk_buf)),
            lib_error::LIB_OK,
        );
        let vk = vk_buf.into_vec();

        let results =
            crate::key_import::tests::run_key_import(3, 2, &sk, &vk);
        let pkp = &results[0].1;

        let mut extras_buf = tss_buffer::empty();
        assert_eq!(
            frozt_derive_sapling_extras_from_seed(Some(&seed_slice), 0, Some(&mut extras_buf)),
            lib_error::LIB_OK,
        );
        let extras = extras_buf.into_vec();

        let pkp_slice = go_slice::from(pkp.as_slice());
        let extras_slice = go_slice::from(extras.as_slice());
        let mut addr_buf = tss_buffer::empty();
        assert_eq!(
            frozt_sapling_derive_address(
                Some(&pkp_slice),
                Some(&extras_slice),
                Some(&mut addr_buf),
            ),
            lib_error::LIB_OK,
        );
        let addr = String::from_utf8(addr_buf.into_vec()).unwrap();

        let expected = "zs1s82p0h0689ccjdfe39tvlzj6hyp2ukqrukfdvdd8cgqfgnexc958uzt0nshx2vk2l9xmxzun7vq";
        assert_eq!(addr, expected, "z-address should match known wallet address");
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
    fn test_sapling_seedless_derive_address() {
        let results = crate::keygen::tests::run_dkg(3, 2);
        assert!(!results.is_empty());
        let pkp = &results[0].1;

        let mut extras_buf = tss_buffer::empty();
        assert_eq!(
            frozt_sapling_generate_extras(Some(&mut extras_buf)),
            lib_error::LIB_OK,
        );
        let extras = extras_buf.into_vec();

        let pkp_slice = go_slice::from(pkp.as_slice());
        let extras_slice = go_slice::from(extras.as_slice());
        let mut addr_buf = tss_buffer::empty();
        assert_eq!(
            frozt_sapling_derive_address(
                Some(&pkp_slice),
                Some(&extras_slice),
                Some(&mut addr_buf),
            ),
            lib_error::LIB_OK,
        );
        let addr = String::from_utf8(addr_buf.into_vec()).unwrap();
        assert!(addr.starts_with("zs"), "address should start with zs: {}", addr);
    }

    #[test]
    fn test_sapling_second_mnemonic_verification() {
        // "divorce ride face oxygen tank fossil trim aunt exact beauty evoke entry"
        let seed = hex::decode(
            "23068a91016aea698ecaed597ef3c9faffcd849f500f9bb9462eae0fa5229685\
             316ce51f7da4dc90dc98cfadb3e4756ace08e85cfe5d0d25c0acdf96e30363b9"
        ).unwrap();

        let seed_slice = go_slice::from(seed.as_slice());
        let mut sk_buf = tss_buffer::empty();
        assert_eq!(
            key_import::frozt_derive_spending_key_from_seed(Some(&seed_slice), 0, Some(&mut sk_buf)),
            lib_error::LIB_OK,
        );
        let sk = sk_buf.into_vec();

        let sk_slice = go_slice::from(sk.as_slice());
        let mut vk_buf = tss_buffer::empty();
        assert_eq!(
            key_import::frozt_spending_key_to_verifying_key(Some(&sk_slice), Some(&mut vk_buf)),
            lib_error::LIB_OK,
        );
        let vk = vk_buf.into_vec();

        let results = crate::key_import::tests::run_key_import(3, 2, &sk, &vk);
        let pkp = &results[0].1;

        let mut extras_buf = tss_buffer::empty();
        assert_eq!(
            frozt_derive_sapling_extras_from_seed(Some(&seed_slice), 0, Some(&mut extras_buf)),
            lib_error::LIB_OK,
        );
        let extras = extras_buf.into_vec();

        let pkp_slice = go_slice::from(pkp.as_slice());
        let extras_slice = go_slice::from(extras.as_slice());
        let mut addr_buf = tss_buffer::empty();
        assert_eq!(
            frozt_sapling_derive_address(
                Some(&pkp_slice),
                Some(&extras_slice),
                Some(&mut addr_buf),
            ),
            lib_error::LIB_OK,
        );
        let addr = String::from_utf8(addr_buf.into_vec()).unwrap();

        let expected = "zs1ghykkprzrcdpkyye0skmddldfhcxj8w4x7kvm9yvm739z2h9xxdqy7n8ntv4p36032zww8pv6e8";
        assert_eq!(addr, expected, "z-address should match wallet for divorce mnemonic");

        crate::sign::tests::run_sign(&results, &[0, 1]);
        crate::sign::tests::run_sign(&results, &[1, 2]);
    }

    #[test]
    fn test_sapling_extras_rejects_out_of_range_account_index() {
        let seed = [0xABu8; 64];
        let seed_slice = go_slice::from(seed.as_slice());
        let mut extras_buf = tss_buffer::empty();

        assert_eq!(
            frozt_derive_sapling_extras_from_seed(
                Some(&seed_slice),
                1u32 << 31,
                Some(&mut extras_buf),
            ),
            lib_error::LIB_SAPLING_ERROR,
        );
    }
}
