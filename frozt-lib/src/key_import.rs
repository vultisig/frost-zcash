use frost_core::{
    keys::{dkg, CoefficientCommitment, VerifiableSecretSharingCommitment},
    Ciphersuite, Field, Group,
};
use reddsa::frost::redjubjub::JubjubBlake2b512;
use sapling_crypto::zip32::ExtendedSpendingKey;
use zip32::ChildIndex;

use crate::{
    bytes::*,
    errors::*,
    handle::Handle,
    keygen::{decode_r1_map, decode_r2_map},
};

type J = JubjubBlake2b512;
type Identifier = frost_core::Identifier<J>;
type F = <<J as Ciphersuite>::Group as Group>::Field;
type G = <J as Ciphersuite>::Group;

fn ser_err<E: std::fmt::Debug>(e: E) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("frozt serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

#[no_mangle]
pub extern "C" fn frozt_derive_spending_key_from_seed(
    seed: Option<&go_slice>,
    account_index: u32,
    out_spending_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let seed_data = seed.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_sk = out_spending_key.ok_or(lib_error::LIB_NULL_PTR)?;

        if seed_data.len() != 64 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let master = ExtendedSpendingKey::master(seed_data.as_slice());
        let path = [
            ChildIndex::hardened(32),
            ChildIndex::hardened(133),
            ChildIndex::hardened(account_index),
        ];
        let child = ExtendedSpendingKey::from_path(&master, &path);
        let ask_bytes = child.expsk.ask.to_bytes();

        *out_sk = tss_buffer::from_vec(ask_bytes.to_vec());

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frozt_spending_key_to_verifying_key(
    spending_key: Option<&go_slice>,
    out_verifying_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sk_data = spending_key.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_vk = out_verifying_key.ok_or(lib_error::LIB_NULL_PTR)?;

        let sk_arr: &[u8; 32] = sk_data.as_slice()
            .try_into()
            .map_err(|_| lib_error::LIB_INVALID_BUFFER_SIZE)?;
        let scalar = F::deserialize(sk_arr).map_err(ser_err)?;
        let point = G::generator() * scalar;
        let vk_bytes =
            <J as Ciphersuite>::Group::serialize(&point).map_err(ser_err)?;

        *out_vk = tss_buffer::from_vec(vk_bytes.as_ref().to_vec());

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frozt_key_import_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    spending_key: Option<&go_slice>,
    out_secret: Option<&mut Handle>,
    out_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_secret = out_secret.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_package = out_package.ok_or(lib_error::LIB_NULL_PTR)?;

        if min_signers < 2 || max_signers < min_signers {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }

        let id = Identifier::try_from(identifier)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        let constant_term = match spending_key {
            Some(sk_data) if !sk_data.is_empty() => {
                let sk_arr: &[u8; 32] = sk_data.as_slice()
                    .try_into()
                    .map_err(|_| lib_error::LIB_INVALID_BUFFER_SIZE)?;
                let sk_scalar = F::deserialize(sk_arr).map_err(ser_err)?;
                let num_others = (max_signers - 1) as u64;
                let mut result = sk_scalar;
                for _ in 0..num_others {
                    result = result - F::one();
                }
                result
            }
            _ => F::one(),
        };

        let mut rng = rand::thread_rng();

        let mut coefficients = Vec::with_capacity(min_signers as usize);
        coefficients.push(constant_term);
        for _ in 1..min_signers {
            coefficients.push(F::random(&mut rng));
        }

        let commitments: Vec<CoefficientCommitment<J>> = coefficients
            .iter()
            .map(|c| CoefficientCommitment::new(G::generator() * *c))
            .collect();

        let commitment = VerifiableSecretSharingCommitment::new(commitments);

        let proof =
            dkg::compute_proof_of_knowledge::<J, _>(id, &coefficients, &commitment, &mut rng)
                .map_err(|_| lib_error::LIB_KEY_IMPORT_ERROR)?;

        let secret = dkg::round1::SecretPackage::new(
            id,
            coefficients,
            commitment.clone(),
            min_signers,
            max_signers,
        );

        let package = dkg::round1::Package::new(commitment, proof);
        let pkg_bytes = package.serialize().map_err(ser_err)?;

        *out_secret = Handle::allocate(secret)?;
        *out_package = tss_buffer::from_vec(pkg_bytes);

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frozt_key_import_part3(
    secret: Handle,
    round1_packages: Option<&go_slice>,
    round2_packages: Option<&go_slice>,
    expected_vk: Option<&go_slice>,
    out_key_package: Option<&mut tss_buffer>,
    out_pub_key_package: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let r1_data = round1_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let r2_data = round2_packages.ok_or(lib_error::LIB_NULL_PTR)?;
        let vk_data = expected_vk.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_kp = out_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_pkp = out_pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;

        let secret_pkg = secret.take::<dkg::round2::SecretPackage<J>>()?;
        let r1_pkgs = decode_r1_map(r1_data.as_slice())?;
        let r2_pkgs = decode_r2_map(r2_data.as_slice())?;

        let (key_package, pub_key_package) =
            dkg::part3(&secret_pkg, &r1_pkgs, &r2_pkgs)
                .map_err(|_| lib_error::LIB_DKG_ERROR)?;

        let vk_bytes = pub_key_package.verifying_key().serialize().map_err(ser_err)?;
        if <[u8]>::ne(vk_bytes.as_ref(), vk_data.as_slice()) {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }

        let kp_bytes = key_package.serialize().map_err(ser_err)?;
        let pkp_bytes = pub_key_package.serialize().map_err(ser_err)?;

        *out_kp = tss_buffer::from_vec(kp_bytes);
        *out_pkp = tss_buffer::from_vec(pkp_bytes);

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frozt_derive_z_address_from_seed(
    pub_key_package: Option<&go_slice>,
    seed: Option<&go_slice>,
    account_index: u32,
    out_address: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let seed_data = seed.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_address.ok_or(lib_error::LIB_NULL_PTR)?;

        if seed_data.len() != 64 {
            return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
        }

        let pkp = frost_core::keys::PublicKeyPackage::<J>::deserialize(pkp_data.as_slice())
            .map_err(ser_err)?;
        let group_vk = pkp.verifying_key().serialize().map_err(ser_err)?;

        let master = ExtendedSpendingKey::master(seed_data.as_slice());
        let path = [
            ChildIndex::hardened(32),
            ChildIndex::hardened(133),
            ChildIndex::hardened(account_index),
        ];
        let child = ExtendedSpendingKey::from_path(&master, &path);

        let ask_bytes = child.expsk.ask.to_bytes();
        let sk_arr: &[u8; 32] = &ask_bytes;
        let expected_scalar = F::deserialize(sk_arr).map_err(ser_err)?;
        let expected_ak = G::serialize(&(G::generator() * expected_scalar))
            .map_err(ser_err)?;
        if expected_ak.as_ref() as &[u8] != group_vk.as_slice() {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }

        let (_, addr) = child.default_address();

        let hrp = bech32::Hrp::parse("zs")
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        let encoded = bech32::encode::<bech32::Bech32>(hrp, &addr.to_bytes())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        *out = tss_buffer::from_vec(encoded.into_bytes());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;
    use crate::keygen::tests::{decode_test_map, encode_test_map};
    use crate::sign::tests::run_sign;

    fn run_key_import(
        n: u16,
        t: u16,
        spending_key: &[u8],
        expected_vk: &[u8],
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let sk_slice = go_slice::from(spending_key);

        let mut secrets1 = Vec::new();
        let mut packages1 = Vec::new();

        for i in 1..=n {
            let mut secret = Handle::null();
            let mut package = tss_buffer::empty();

            let sk_opt = if i == 1 { Some(&sk_slice) } else { None };

            assert_eq!(
                frozt_key_import_part1(
                    i,
                    n,
                    t,
                    sk_opt,
                    Some(&mut secret),
                    Some(&mut package),
                ),
                lib_error::LIB_OK,
            );

            secrets1.push(secret);
            packages1.push((i, package.into_vec()));
        }

        let mut secrets2 = Vec::new();
        let mut all_r2_packages: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

        for i in 0..n as usize {
            let others: Vec<_> = packages1
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (id, pkg))| (*id, pkg.clone()))
                .collect();

            let r1_map = encode_test_map(&others);
            let r1_slice = go_slice::from(r1_map.as_slice());

            let mut secret = Handle::null();
            let mut packages = tss_buffer::empty();

            assert_eq!(
                keygen::frozt_dkg_part2(
                    secrets1[i],
                    Some(&r1_slice),
                    Some(&mut secret),
                    Some(&mut packages),
                ),
                lib_error::LIB_OK,
            );

            secrets2.push(secret);
            let r2_bytes = packages.into_vec();
            all_r2_packages.push(decode_test_map(&r2_bytes));
        }

        let mut results = Vec::new();

        for i in 0..n as usize {
            let r1_others: Vec<_> = packages1
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (id, pkg))| (*id, pkg.clone()))
                .collect();

            let my_id = (i + 1) as u16;
            let mut r2_for_me = Vec::new();
            for (sender_idx, r2_pkgs) in all_r2_packages.iter().enumerate() {
                if sender_idx == i {
                    continue;
                }
                let sender_id = (sender_idx + 1) as u16;
                for (recipient_id, pkg_bytes) in r2_pkgs {
                    if *recipient_id == my_id {
                        r2_for_me.push((sender_id, pkg_bytes.clone()));
                    }
                }
            }

            let r1_map = encode_test_map(&r1_others);
            let r2_map = encode_test_map(&r2_for_me);
            let r1_slice = go_slice::from(r1_map.as_slice());
            let r2_slice = go_slice::from(r2_map.as_slice());
            let vk_slice = go_slice::from(expected_vk);

            let mut kp = tss_buffer::empty();
            let mut pkp = tss_buffer::empty();

            assert_eq!(
                frozt_key_import_part3(
                    secrets2[i],
                    Some(&r1_slice),
                    Some(&r2_slice),
                    Some(&vk_slice),
                    Some(&mut kp),
                    Some(&mut pkp),
                ),
                lib_error::LIB_OK,
            );

            results.push((kp.into_vec(), pkp.into_vec()));
        }

        results
    }

    fn derive_test_key(account: u32) -> (Vec<u8>, Vec<u8>) {
        let seed = [0xABu8; 64];
        let seed_slice = go_slice::from(seed.as_slice());

        let mut sk_buf = tss_buffer::empty();
        assert_eq!(
            frozt_derive_spending_key_from_seed(
                Some(&seed_slice),
                account,
                Some(&mut sk_buf),
            ),
            lib_error::LIB_OK,
        );
        let sk = sk_buf.into_vec();

        let sk_slice = go_slice::from(sk.as_slice());
        let mut vk_buf = tss_buffer::empty();
        assert_eq!(
            frozt_spending_key_to_verifying_key(Some(&sk_slice), Some(&mut vk_buf)),
            lib_error::LIB_OK,
        );
        let vk = vk_buf.into_vec();

        (sk, vk)
    }

    #[test]
    fn test_key_import_2of3() {
        let (sk, vk) = derive_test_key(0);

        let results = run_key_import(3, 2, &sk, &vk);
        assert_eq!(results.len(), 3);

        run_sign(&results, &[0, 1]);
        run_sign(&results, &[1, 2]);
    }

    #[test]
    fn test_key_import_3of4() {
        let (sk, vk) = derive_test_key(1);

        let results = run_key_import(4, 3, &sk, &vk);
        assert_eq!(results.len(), 4);

        run_sign(&results, &[0, 1, 2]);
        run_sign(&results, &[1, 2, 3]);
    }

    #[test]
    fn test_derivation_chain_integrity() {
        use group::GroupEncoding;
        use sapling_crypto::{
            constants::PROOF_GENERATION_KEY_GENERATOR,
            keys::{FullViewingKey, NullifierDerivingKey},
            zip32::sapling_default_address,
        };

        let seed = hex::decode(
            "c829196323d2eea891b2b6a01e0f10f31645a339e0b1ab0c1f3184d6ac58589a\
             2fdab5c19437877ba33887541a27436eb287393dea0265a3681da5e6f5853627"
        ).unwrap();

        let master = ExtendedSpendingKey::master(&seed);
        let path = [
            ChildIndex::hardened(32),
            ChildIndex::hardened(133),
            ChildIndex::hardened(0),
        ];
        let child = ExtendedSpendingKey::from_path(&master, &path);

        let ask_bytes = child.expsk.ask.to_bytes();

        let ask_scalar = F::deserialize(&ask_bytes).unwrap();
        let frost_ak = G::generator() * ask_scalar;
        let frost_ak_bytes = G::serialize(&frost_ak).unwrap();

        let fvk = FullViewingKey::from_expanded_spending_key(&child.expsk);
        let sapling_ak_bytes = fvk.vk.ak.to_bytes();

        assert_eq!(
            frost_ak_bytes.as_ref(),
            &sapling_ak_bytes[..],
            "FROST generator * ask must equal sapling SpendValidatingKey"
        );

        let nk = NullifierDerivingKey(PROOF_GENERATION_KEY_GENERATOR * child.expsk.nsk);
        let _nk_bytes = nk.0.to_bytes();

        let _ivk = fvk.vk.ivk();

        let (_, dk) = {
            let xsk_bytes = child.to_bytes();
            let dk_slice = &xsk_bytes[137..169];
            ((), sapling_crypto::zip32::DiversifierKey::from_bytes(dk_slice.try_into().unwrap()))
        };

        let (_, addr) = sapling_default_address(&fvk, &dk);

        let z_addr = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("zs").unwrap(),
            &addr.to_bytes(),
        ).unwrap();

        assert_eq!(
            z_addr,
            "zs1s82p0h0689ccjdfe39tvlzj6hyp2ukqrukfdvdd8cgqfgnexc958uzt0nshx2vk2l9xmxzun7vq"
        );

        let results = run_key_import(3, 2, &ask_bytes, frost_ak_bytes.as_ref());
        let pkp = frost_core::keys::PublicKeyPackage::<J>::deserialize(&results[0].1).unwrap();
        let frost_group_vk = pkp.verifying_key().serialize().unwrap();

        assert_eq!(
            frost_group_vk.as_slice(),
            &sapling_ak_bytes[..],
            "FROST group VK must match sapling ak"
        );
        assert_eq!(
            frost_group_vk.as_slice(),
            frost_ak_bytes.as_ref(),
            "FROST group VK must match FROST generator * ask"
        );

        run_sign(&results, &[0, 1]);
        run_sign(&results, &[1, 2]);
    }

    #[test]
    fn test_blind_mnemonic_verification() {
        use sapling_crypto::keys::FullViewingKey;
        use sapling_crypto::zip32::sapling_default_address;

        // "divorce ride face oxygen tank fossil trim aunt exact beauty evoke entry"
        let seed = hex::decode(
            "23068a91016aea698ecaed597ef3c9faffcd849f500f9bb9462eae0fa5229685\
             316ce51f7da4dc90dc98cfadb3e4756ace08e85cfe5d0d25c0acdf96e30363b9"
        ).unwrap();

        let master = ExtendedSpendingKey::master(&seed);
        let path = [
            ChildIndex::hardened(32),
            ChildIndex::hardened(133),
            ChildIndex::hardened(0),
        ];
        let child = ExtendedSpendingKey::from_path(&master, &path);

        let ask_bytes = child.expsk.ask.to_bytes();
        let ask_scalar = F::deserialize(&ask_bytes).unwrap();
        let frost_ak = G::generator() * ask_scalar;
        let frost_ak_bytes = G::serialize(&frost_ak).unwrap();

        let fvk = FullViewingKey::from_expanded_spending_key(&child.expsk);
        let sapling_ak_bytes = fvk.vk.ak.to_bytes();
        assert_eq!(frost_ak_bytes.as_ref(), &sapling_ak_bytes[..]);

        let xsk_bytes = child.to_bytes();
        let dk = sapling_crypto::zip32::DiversifierKey::from_bytes(
            xsk_bytes[137..169].try_into().unwrap(),
        );
        let (_, addr) = sapling_default_address(&fvk, &dk);

        let _z_addr = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("zs").unwrap(),
            &addr.to_bytes(),
        ).unwrap();

        let results = run_key_import(3, 2, &ask_bytes, frost_ak_bytes.as_ref());
        run_sign(&results, &[0, 1]);
        run_sign(&results, &[1, 2]);
    }

    #[test]
    fn test_key_import_mnemonic_seed() {
        // BIP39 seed for: "pull army pride tribe debris trim evoke inmate lift sure
        // parent deny school trumpet owner ensure picture spare foil object junior
        // favorite potato enforce" (empty passphrase)
        let seed = hex::decode(
            "c829196323d2eea891b2b6a01e0f10f31645a339e0b1ab0c1f3184d6ac58589a\
             2fdab5c19437877ba33887541a27436eb287393dea0265a3681da5e6f5853627"
        ).unwrap();
        assert_eq!(seed.len(), 64);

        let seed_slice = go_slice::from(seed.as_slice());
        let mut sk_buf = tss_buffer::empty();
        assert_eq!(
            frozt_derive_spending_key_from_seed(Some(&seed_slice), 0, Some(&mut sk_buf)),
            lib_error::LIB_OK,
        );
        let sk = sk_buf.into_vec();

        let sk_slice = go_slice::from(sk.as_slice());
        let mut vk_buf = tss_buffer::empty();
        assert_eq!(
            frozt_spending_key_to_verifying_key(Some(&sk_slice), Some(&mut vk_buf)),
            lib_error::LIB_OK,
        );
        let vk = vk_buf.into_vec();

        let results = run_key_import(3, 2, &sk, &vk);
        assert_eq!(results.len(), 3);

        run_sign(&results, &[0, 1]);
        run_sign(&results, &[1, 2]);
        run_sign(&results, &[0, 2]);

        let pkp = frost_core::keys::PublicKeyPackage::<J>::deserialize(&results[0].1).unwrap();
        let group_vk = pkp.verifying_key().serialize().unwrap();
        assert_eq!(group_vk, vk);

        let master = ExtendedSpendingKey::master(&seed);
        let path = [
            ChildIndex::hardened(32),
            ChildIndex::hardened(133),
            ChildIndex::hardened(0),
        ];
        let child = ExtendedSpendingKey::from_path(&master, &path);
        let (_, addr) = child.default_address();
        let z_addr = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("zs").unwrap(),
            &addr.to_bytes(),
        ).unwrap();
        let expected_z_addr = "zs1s82p0h0689ccjdfe39tvlzj6hyp2ukqrukfdvdd8cgqfgnexc958uzt0nshx2vk2l9xmxzun7vq";
        assert_eq!(z_addr, expected_z_addr, "z-address should match wallet");
    }
}
