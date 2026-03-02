use ff::PrimeField;
use frost_core::{
    keys::{dkg, CoefficientCommitment, VerifiableSecretSharingCommitment},
    Ciphersuite, Field, Group,
};
use sapling_crypto::zip32::ExtendedSpendingKey;
use wasm_bindgen::prelude::*;
use zip32::ChildIndex;

use crate::{js_obj, keygen, set_bytes, to_js_err, Identifier, J};

type F = <<J as Ciphersuite>::Group as Group>::Field;
type G = <J as Ciphersuite>::Group;

fn hardened_account_child(account_index: u32) -> Result<ChildIndex, JsError> {
    if account_index >= (1u32 << 31) {
        return Err(JsError::new("account index out of range; expected 0..2^31-1"));
    }
    Ok(ChildIndex::hardened(account_index))
}

fn derive_spending_key(seed: &[u8], account_index: u32) -> Result<[u8; 32], JsError> {
    if seed.len() != 64 {
        return Err(JsError::new("seed must be 64 bytes"));
    }
    let master = ExtendedSpendingKey::master(seed);
    let account = hardened_account_child(account_index)?;
    let path = [
        ChildIndex::hardened(32),
        ChildIndex::hardened(133),
        account,
    ];
    let child = ExtendedSpendingKey::from_path(&master, &path);
    Ok(child.expsk.ask.to_bytes())
}

fn spending_key_to_vk(spending_key: &[u8; 32]) -> Result<Vec<u8>, JsError> {
    let scalar = F::deserialize(spending_key).map_err(to_js_err)?;
    let point = G::generator() * scalar;
    let vk_bytes = <J as Ciphersuite>::Group::serialize(&point).map_err(to_js_err)?;
    Ok(vk_bytes.as_ref().to_vec())
}

fn derive_extras_from_seed(seed: &[u8], account_index: u32) -> Result<Vec<u8>, JsError> {
    if seed.len() != 64 {
        return Err(JsError::new("seed must be 64 bytes"));
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

    let mut extras = vec![0u8; 96];
    let mut nsk_repr = child.expsk.nsk.to_repr();
    extras[..32].copy_from_slice(&nsk_repr);
    zeroize::Zeroize::zeroize(&mut nsk_repr);
    extras[32..64].copy_from_slice(&child.expsk.ovk.0);
    extras[64..96].copy_from_slice(&dfvk_bytes[96..128]);

    Ok(extras)
}

#[wasm_bindgen]
pub fn frozt_key_import_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    seed: Option<Vec<u8>>,
    account_index: u32,
) -> Result<JsValue, JsError> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(JsError::new("invalid signers: need min >= 2 and max >= min"));
    }

    let id = Identifier::try_from(identifier).map_err(to_js_err)?;

    let obj = js_obj();

    let constant_term = match seed {
        Some(ref seed_data) if !seed_data.is_empty() => {
            let sk = derive_spending_key(seed_data, account_index)?;
            let vk = spending_key_to_vk(&sk)?;
            let extras = derive_extras_from_seed(seed_data, account_index)?;

            set_bytes(&obj, "verifyingKey", &vk);
            set_bytes(&obj, "extras", &extras);

            let sk_scalar = F::deserialize(&sk).map_err(to_js_err)?;
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

    let proof = dkg::compute_proof_of_knowledge::<J, _>(
        id,
        &coefficients,
        &commitment,
        &mut rng,
    )
    .map_err(to_js_err)?;

    let secret = dkg::round1::SecretPackage::new(
        id,
        coefficients,
        commitment.clone(),
        min_signers,
        max_signers,
    );

    let package = dkg::round1::Package::new(commitment, proof);

    let secret_bytes = secret.serialize().map_err(to_js_err)?;
    let pkg_bytes = package.serialize().map_err(to_js_err)?;

    set_bytes(&obj, "secret", &secret_bytes);
    set_bytes(&obj, "package", &pkg_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frozt_key_import_part3(
    secret: &[u8],
    round1_packages: &[u8],
    round2_packages: &[u8],
    expected_vk: &[u8],
) -> Result<JsValue, JsError> {
    let secret_pkg =
        dkg::round2::SecretPackage::<J>::deserialize(secret).map_err(to_js_err)?;
    let r1_pkgs = keygen::decode_r1_map(round1_packages)?;
    let r2_pkgs = keygen::decode_r2_map(round2_packages)?;

    let (key_package, pub_key_package) =
        dkg::part3(&secret_pkg, &r1_pkgs, &r2_pkgs).map_err(to_js_err)?;

    let vk_bytes = pub_key_package
        .verifying_key()
        .serialize()
        .map_err(to_js_err)?;
    if vk_bytes.as_ref() as &[u8] != expected_vk {
        return Err(JsError::new(
            "verifying key mismatch after key import",
        ));
    }

    let kp_bytes = key_package.serialize().map_err(to_js_err)?;
    let pkp_bytes = pub_key_package.serialize().map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "keyPackage", &kp_bytes);
    set_bytes(&obj, "pubKeyPackage", &pkp_bytes);
    Ok(obj.into())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use frost_core::keys::dkg;
    use crate::keygen;
    use wasm_bindgen_test::*;

    pub struct KeyImportResult {
        pub results: Vec<(Vec<u8>, Vec<u8>)>,
        pub vk: Vec<u8>,
        pub extras: Vec<u8>,
    }

    #[test]
    fn test_derive_spending_key_deterministic() {
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap();
        let sk1 = derive_spending_key(&seed, 0).unwrap();
        let sk2 = derive_spending_key(&seed, 0).unwrap();
        assert_eq!(sk1.len(), 32);
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn test_derive_spending_key_different_accounts() {
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap();
        let sk0 = derive_spending_key(&seed, 0).unwrap();
        let sk1 = derive_spending_key(&seed, 1).unwrap();
        assert_ne!(sk0, sk1);
    }

    #[test]
    fn test_spending_key_to_verifying_key() {
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap();
        let sk = derive_spending_key(&seed, 0).unwrap();
        let vk = spending_key_to_vk(&sk).unwrap();
        assert_eq!(vk.len(), 32);

        let vk2 = spending_key_to_vk(&sk).unwrap();
        assert_eq!(vk, vk2);
    }

    #[test]
    fn test_key_import_full_flow() {
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap();
        let import = run_key_import_native(3, 2, &seed, 0);
        assert_eq!(import.results.len(), 3);

        let pkp0 = frost_core::keys::PublicKeyPackage::<J>::deserialize(&import.results[0].1).unwrap();
        let pkp1 = frost_core::keys::PublicKeyPackage::<J>::deserialize(&import.results[1].1).unwrap();
        let vk_bytes: Vec<u8> = pkp0.verifying_key().serialize().unwrap();
        assert_eq!(&vk_bytes[..], &import.vk[..]);
        assert_eq!(pkp0.verifying_key(), pkp1.verifying_key());
    }

    #[wasm_bindgen_test]
    fn test_derive_spending_key_deterministic_wasm() {
        test_derive_spending_key_deterministic();
    }

    #[wasm_bindgen_test]
    fn test_derive_spending_key_different_accounts_wasm() {
        test_derive_spending_key_different_accounts();
    }

    #[wasm_bindgen_test]
    fn test_spending_key_to_verifying_key_wasm() {
        test_spending_key_to_verifying_key();
    }

    #[wasm_bindgen_test]
    fn test_key_import_full_flow_wasm() {
        test_key_import_full_flow();
    }

    pub(crate) fn run_key_import_native(
        n: u16,
        t: u16,
        seed: &[u8],
        account_index: u32,
    ) -> KeyImportResult {
        let sk = derive_spending_key(seed, account_index).unwrap();
        let vk = spending_key_to_vk(&sk).unwrap();
        let extras = derive_extras_from_seed(seed, account_index).unwrap();
        let sk_scalar = F::deserialize(&sk).unwrap();

        let mut secrets1 = Vec::new();
        let mut packages1 = Vec::new();

        for i in 1..=n {
            let id = Identifier::try_from(i).unwrap();

            let constant_term = if i == 1 {
                let num_others = (n - 1) as u64;
                let mut result = sk_scalar;
                for _ in 0..num_others {
                    result = result - F::one();
                }
                result
            } else {
                F::one()
            };

            let mut rng = rand::thread_rng();
            let mut coefficients = Vec::with_capacity(t as usize);
            coefficients.push(constant_term);
            for _ in 1..t {
                coefficients.push(F::random(&mut rng));
            }

            let commitments: Vec<CoefficientCommitment<J>> = coefficients
                .iter()
                .map(|c| CoefficientCommitment::new(G::generator() * *c))
                .collect();
            let commitment = VerifiableSecretSharingCommitment::new(commitments);

            let proof = dkg::compute_proof_of_knowledge::<J, _>(
                id, &coefficients, &commitment, &mut rng,
            ).unwrap();

            let secret = dkg::round1::SecretPackage::new(
                id, coefficients, commitment.clone(), t, n,
            );
            let package = dkg::round1::Package::new(commitment, proof);

            secrets1.push(secret.serialize().unwrap());
            packages1.push((i, package.serialize().unwrap()));
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

            let r1_map = keygen::tests::encode_id_map_native(&others);
            let secret_pkg =
                dkg::round1::SecretPackage::<J>::deserialize(&secrets1[i]).unwrap();
            let r1_pkgs = keygen::decode_r1_map(&r1_map).unwrap();
            let (secret2, r2_pkgs) = dkg::part2(secret_pkg, &r1_pkgs).unwrap();

            let secret2_bytes = secret2.serialize().unwrap();
            let r2_bytes = keygen::encode_r2_map(&r2_pkgs).unwrap();
            let r2_decoded = keygen::tests::decode_id_map(&r2_bytes);

            secrets2.push(secret2_bytes);
            all_r2_packages.push(r2_decoded);
        }

        let mut results = Vec::new();

        for i in 0..n as usize {
            let r1_others: Vec<_> = packages1
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (id, pkg))| (*id, pkg.clone()))
                .collect();

            let mut r2_for_me = Vec::new();
            let my_id = (i + 1) as u16;
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

            let r1_map = keygen::tests::encode_id_map_native(&r1_others);
            let r2_map = keygen::tests::encode_id_map_native(&r2_for_me);

            let secret_pkg =
                dkg::round2::SecretPackage::<J>::deserialize(&secrets2[i]).unwrap();
            let r1_pkgs = keygen::decode_r1_map(&r1_map).unwrap();
            let r2_pkgs = keygen::decode_r2_map(&r2_map).unwrap();
            let (key_package, pub_key_package) =
                dkg::part3(&secret_pkg, &r1_pkgs, &r2_pkgs).unwrap();

            let vk_bytes = pub_key_package.verifying_key().serialize().unwrap();
            assert_eq!(
                vk_bytes.as_ref() as &[u8],
                &vk[..],
                "VK mismatch for party {}",
                my_id,
            );

            results.push((
                key_package.serialize().unwrap(),
                pub_key_package.serialize().unwrap(),
            ));
        }

        KeyImportResult { results, vk, extras }
    }
}
