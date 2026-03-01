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
    zeroize_scalar_vec,
};

type J = JubjubBlake2b512;
type Identifier = frost_core::Identifier<J>;
type F = <<J as Ciphersuite>::Group as Group>::Field;
type G = <J as Ciphersuite>::Group;

fn hardened_account_child(account_index: u32) -> Result<ChildIndex, lib_error> {
    if account_index >= (1u32 << 31) {
        return Err(lib_error::LIB_KEY_IMPORT_ERROR);
    }
    Ok(ChildIndex::hardened(account_index))
}

fn ser_err<E: std::fmt::Debug>(e: E) -> lib_error {
    #[cfg(debug_assertions)]
    eprintln!("frozt serialization error: {:?}", e);
    let _ = e;
    lib_error::LIB_SERIALIZATION_ERROR
}

fn derive_spending_key(seed: &[u8], account_index: u32) -> Result<[u8; 32], lib_error> {
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
    let mut ask_bytes = child.expsk.ask.to_bytes();
    let result = ask_bytes;
    zeroize::Zeroize::zeroize(&mut ask_bytes);
    Ok(result)
}

fn spending_key_to_vk(spending_key: &[u8; 32]) -> Result<Vec<u8>, lib_error> {
    let scalar = F::deserialize(spending_key).map_err(ser_err)?;
    let point = G::generator() * scalar;
    let vk_bytes =
        <J as Ciphersuite>::Group::serialize(&point).map_err(ser_err)?;
    Ok(vk_bytes.as_ref().to_vec())
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_key_import_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    seed: Option<&go_slice>,
    account_index: u32,
    out_secret: Option<&mut Handle>,
    out_package: Option<&mut tss_buffer>,
    out_vk: Option<&mut tss_buffer>,
    out_extras: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out_secret = out_secret.ok_or(lib_error::LIB_NULL_PTR)?;
        let out_package = out_package.ok_or(lib_error::LIB_NULL_PTR)?;

        if min_signers < 2 || max_signers < min_signers {
            return Err(lib_error::LIB_KEY_IMPORT_ERROR);
        }

        let id = Identifier::try_from(identifier)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;

        let constant_term = match seed {
            Some(seed_data) if !seed_data.is_empty() => {
                let sk = derive_spending_key(seed_data.as_slice(), account_index)?;
                let vk = spending_key_to_vk(&sk)?;
                let extras = crate::sapling::derive_extras_from_seed(seed_data.as_slice(), account_index)?;

                if let Some(out_v) = out_vk {
                    *out_v = tss_buffer::from_vec(vk);
                }
                if let Some(out_e) = out_extras {
                    *out_e = tss_buffer::from_vec(extras);
                }

                let sk_scalar = F::deserialize(&sk).map_err(ser_err)?;
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
            coefficients.clone(),
            commitment.clone(),
            min_signers,
            max_signers,
        );

        zeroize_scalar_vec(&mut coefficients);

        let package = dkg::round1::Package::new(commitment, proof);
        let pkg_bytes = package.serialize().map_err(ser_err)?;

        *out_secret = Handle::allocate(secret)?;
        *out_package = tss_buffer::from_vec(pkg_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keygen;
    use crate::keygen::tests::{decode_test_map, encode_test_map};
    use crate::sign::tests::run_sign;

    pub struct KeyImportResult {
        pub results: Vec<(Vec<u8>, Vec<u8>)>,
        pub vk: Vec<u8>,
        pub extras: Vec<u8>,
    }

    pub fn run_key_import(
        n: u16,
        t: u16,
        seed: &[u8],
        account_index: u32,
    ) -> KeyImportResult {
        let seed_slice = go_slice::from(seed);

        let mut secrets1 = Vec::new();
        let mut packages1 = Vec::new();
        let mut vk = Vec::new();
        let mut extras = Vec::new();

        for i in 1..=n {
            let mut secret = Handle::null();
            let mut package = tss_buffer::empty();
            let mut vk_buf = tss_buffer::empty();
            let mut extras_buf = tss_buffer::empty();

            let seed_opt = if i == 1 { Some(&seed_slice) } else { None };

            assert_eq!(
                frozt_key_import_part1(
                    i,
                    n,
                    t,
                    seed_opt,
                    account_index,
                    Some(&mut secret),
                    Some(&mut package),
                    Some(&mut vk_buf),
                    Some(&mut extras_buf),
                ),
                lib_error::LIB_OK,
            );

            if i == 1 {
                vk = vk_buf.into_vec();
                extras = extras_buf.into_vec();
            }

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
            let vk_slice = go_slice::from(vk.as_slice());

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

        KeyImportResult { results, vk, extras }
    }

    #[test]
    fn test_key_import_2of3() {
        let seed = [0xABu8; 64];

        let import = run_key_import(3, 2, &seed, 0);
        assert_eq!(import.results.len(), 3);

        run_sign(&import.results, &[0, 1]);
        run_sign(&import.results, &[1, 2]);
    }

    #[test]
    fn test_key_import_3of4() {
        let seed = [0xABu8; 64];

        let import = run_key_import(4, 3, &seed, 1);
        assert_eq!(import.results.len(), 4);

        run_sign(&import.results, &[0, 1, 2]);
        run_sign(&import.results, &[1, 2, 3]);
    }

    #[test]
    fn test_key_import_mnemonic_seed() {
        let seed = hex::decode(
            "c829196323d2eea891b2b6a01e0f10f31645a339e0b1ab0c1f3184d6ac58589a\
             2fdab5c19437877ba33887541a27436eb287393dea0265a3681da5e6f5853627"
        ).unwrap();
        assert_eq!(seed.len(), 64);

        let import = run_key_import(3, 2, &seed, 0);
        assert_eq!(import.results.len(), 3);

        run_sign(&import.results, &[0, 1]);
        run_sign(&import.results, &[1, 2]);
        run_sign(&import.results, &[0, 2]);

        let pkp = frost_core::keys::PublicKeyPackage::<J>::deserialize(&import.results[0].1).unwrap();
        let group_vk = pkp.verifying_key().serialize().unwrap();
        assert_eq!(group_vk, import.vk);

        let pkp_slice = go_slice::from(import.results[0].1.as_slice());
        let extras_slice = go_slice::from(import.extras.as_slice());
        let mut addr_buf = tss_buffer::empty();
        let mut ivk_buf = tss_buffer::empty();
        let mut nk_buf = tss_buffer::empty();
        assert_eq!(
            crate::sapling::frozt_sapling_derive_keys(
                Some(&pkp_slice), Some(&extras_slice),
                Some(&mut addr_buf), Some(&mut ivk_buf), Some(&mut nk_buf),
            ),
            lib_error::LIB_OK,
        );
        let z_addr = String::from_utf8(addr_buf.into_vec()).unwrap();
        let expected_z_addr = "zs1s82p0h0689ccjdfe39tvlzj6hyp2ukqrukfdvdd8cgqfgnexc958uzt0nshx2vk2l9xmxzun7vq";
        assert_eq!(z_addr, expected_z_addr, "z-address should match wallet");
    }

    #[test]
    fn test_key_import_rejects_out_of_range_account_index() {
        let seed = [0xABu8; 64];
        let seed_slice = go_slice::from(seed.as_slice());
        let mut secret = Handle::null();
        let mut package = tss_buffer::empty();
        let mut vk_buf = tss_buffer::empty();
        let mut extras_buf = tss_buffer::empty();

        assert_eq!(
            frozt_key_import_part1(
                1, 3, 2,
                Some(&seed_slice),
                1u32 << 31,
                Some(&mut secret),
                Some(&mut package),
                Some(&mut vk_buf),
                Some(&mut extras_buf),
            ),
            lib_error::LIB_KEY_IMPORT_ERROR,
        );
    }
}
