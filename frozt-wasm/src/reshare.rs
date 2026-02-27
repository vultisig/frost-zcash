use frost_core::{
    keys::{dkg, CoefficientCommitment, KeyPackage, VerifiableSecretSharingCommitment},
    Ciphersuite, Field, Group,
};
use wasm_bindgen::prelude::*;

use crate::{
    js_obj, keygen, set_bytes, to_js_err, Identifier, J,
};

type Scalar = frost_core::Scalar<J>;
type F = <<J as Ciphersuite>::Group as Group>::Field;
type G = <J as Ciphersuite>::Group;

fn lagrange_coeff(
    my_id: &Identifier,
    all_ids: &[Identifier],
) -> Result<Scalar, JsError> {
    let xi = my_id.to_scalar();
    let mut num = F::one();
    let mut den = F::one();
    for id in all_ids {
        if id == my_id {
            continue;
        }
        let xj = id.to_scalar();
        num = num * xj;
        den = den * (xj - xi);
    }
    let den_inv = F::invert(&den).map_err(to_js_err)?;
    Ok(num * den_inv)
}

fn decode_old_identifiers(data: &[u8]) -> Result<Vec<Identifier>, JsError> {
    if data.len() % 2 != 0 {
        return Err(JsError::new("old_identifiers: odd byte length"));
    }
    let count = data.len() / 2;
    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        let raw = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
        let id = Identifier::try_from(raw).map_err(to_js_err)?;
        ids.push(id);
    }
    Ok(ids)
}

fn reshare_part1_inner(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    old_key_package: Option<&[u8]>,
    old_identifiers: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), JsError> {
    let id = Identifier::try_from(identifier).map_err(to_js_err)?;

    let additive_share = match old_key_package {
        Some(kp_data) if !kp_data.is_empty() => {
            let old_ids_data = old_identifiers.ok_or_else(|| {
                JsError::new("old_identifiers required for old members")
            })?;
            let old_ids = decode_old_identifiers(old_ids_data)?;
            let kp = KeyPackage::<J>::deserialize(kp_data).map_err(to_js_err)?;
            let di = kp.signing_share().to_scalar();
            let li = lagrange_coeff(kp.identifier(), &old_ids)?;
            let mut share = di * li;

            let num_new = max_signers - old_ids.len() as u16;
            let min_old_id = old_ids
                .iter()
                .min()
                .ok_or_else(|| JsError::new("empty old_ids"))?;
            if kp.identifier() == min_old_id {
                for _ in 0..num_new {
                    share = share - F::one();
                }
            }

            share
        }
        _ => F::one(),
    };

    let mut rng = rand::thread_rng();

    let mut coefficients = Vec::with_capacity(min_signers as usize);
    coefficients.push(additive_share);
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

    Ok((secret_bytes, pkg_bytes))
}

#[wasm_bindgen]
pub fn frozt_reshare_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    old_key_package: Option<Vec<u8>>,
    old_identifiers: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    let (secret_bytes, pkg_bytes) = reshare_part1_inner(
        identifier,
        max_signers,
        min_signers,
        old_key_package.as_deref(),
        old_identifiers.as_deref(),
    )?;

    let obj = js_obj();
    set_bytes(&obj, "secret", &secret_bytes);
    set_bytes(&obj, "package", &pkg_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frozt_reshare_part3(
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
    if <[u8]>::ne(vk_bytes.as_ref(), expected_vk) {
        return Err(JsError::new("reshare: verifying key mismatch"));
    }

    let kp_bytes = key_package.serialize().map_err(to_js_err)?;
    let pkp_bytes = pub_key_package.serialize().map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "keyPackage", &kp_bytes);
    set_bytes(&obj, "pubKeyPackage", &pkp_bytes);
    Ok(obj.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::tests::{decode_id_map, run_dkg_native};
    use frost_core::keys::PublicKeyPackage;

    fn encode_id_map(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (id, v) in entries {
            let id_bytes = Identifier::try_from(*id).unwrap().serialize();
            buf.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&id_bytes);
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(v);
        }
        buf
    }

    fn run_reshare_native(
        old_results: &[(Vec<u8>, Vec<u8>)],
        new_n: u16,
        new_t: u16,
        old_ids: &[u16],
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let pkp = PublicKeyPackage::<J>::deserialize(&old_results[0].1).unwrap();
        let expected_vk = pkp.verifying_key().serialize().unwrap();

        let old_ids_bytes: Vec<u8> =
            old_ids.iter().flat_map(|id| id.to_le_bytes()).collect();

        let mut secrets1 = Vec::new();
        let mut packages1 = Vec::new();

        for i in 1..=new_n {
            let (old_kp, old_ids_arg): (Option<&[u8]>, Option<&[u8]>) =
                if old_ids.contains(&i) {
                    (
                        Some(old_results[(i - 1) as usize].0.as_slice()),
                        Some(old_ids_bytes.as_slice()),
                    )
                } else {
                    (None, None)
                };

            let (secret_bytes, pkg_bytes) =
                reshare_part1_inner(i, new_n, new_t, old_kp, old_ids_arg).unwrap();

            secrets1.push(secret_bytes);
            packages1.push((i, pkg_bytes));
        }

        let mut secrets2 = Vec::new();
        let mut all_r2_packages: Vec<Vec<(u16, Vec<u8>)>> = Vec::new();

        for i in 0..new_n as usize {
            let others: Vec<_> = packages1
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (id, pkg))| (*id, pkg.clone()))
                .collect();

            let r1_map = encode_id_map(&others);

            let secret_pkg =
                dkg::round1::SecretPackage::<J>::deserialize(&secrets1[i]).unwrap();
            let r1_pkgs = keygen::decode_r1_map(&r1_map).unwrap();
            let (secret2, r2_pkgs) = dkg::part2(secret_pkg, &r1_pkgs).unwrap();

            let secret2_bytes = secret2.serialize().unwrap();
            let r2_bytes = keygen::encode_r2_map(&r2_pkgs).unwrap();
            let r2_decoded = decode_id_map(&r2_bytes);

            secrets2.push(secret2_bytes);
            all_r2_packages.push(r2_decoded);
        }

        let mut results = Vec::new();

        for i in 0..new_n as usize {
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

            let r1_map = encode_id_map(&r1_others);
            let r2_map = encode_id_map(&r2_for_me);

            let secret_pkg =
                dkg::round2::SecretPackage::<J>::deserialize(&secrets2[i]).unwrap();
            let r1_pkgs = keygen::decode_r1_map(&r1_map).unwrap();
            let r2_pkgs = keygen::decode_r2_map(&r2_map).unwrap();
            let (key_package, pub_key_package) =
                dkg::part3(&secret_pkg, &r1_pkgs, &r2_pkgs).unwrap();

            let vk_bytes = pub_key_package.verifying_key().serialize().unwrap();
            assert_eq!(vk_bytes.as_slice(), expected_vk.as_slice());

            let kp_bytes = key_package.serialize().unwrap();
            let pkp_bytes = pub_key_package.serialize().unwrap();
            results.push((kp_bytes, pkp_bytes));
        }

        results
    }

    #[test]
    fn test_reshare_2of2_to_2of3() {
        let results_2of2 = run_dkg_native(2, 2);
        let pkp0 = PublicKeyPackage::<J>::deserialize(&results_2of2[0].1).unwrap();
        let vk = pkp0.verifying_key().clone();

        let results_2of3 = run_reshare_native(&results_2of2, 3, 2, &[1, 2]);
        let pkp1 = PublicKeyPackage::<J>::deserialize(&results_2of3[0].1).unwrap();
        assert_eq!(vk, *pkp1.verifying_key());
    }

    #[test]
    fn test_reshare_chain() {
        let results_2of2 = run_dkg_native(2, 2);
        let pkp_initial =
            PublicKeyPackage::<J>::deserialize(&results_2of2[0].1).unwrap();
        let vk = pkp_initial.verifying_key().clone();

        let results_2of3 = run_reshare_native(&results_2of2, 3, 2, &[1, 2]);
        let pkp_2of3 =
            PublicKeyPackage::<J>::deserialize(&results_2of3[0].1).unwrap();
        assert_eq!(vk, *pkp_2of3.verifying_key());

        let results_3of4 = run_reshare_native(&results_2of3, 4, 3, &[1, 2, 3]);
        let pkp_3of4 =
            PublicKeyPackage::<J>::deserialize(&results_3of4[0].1).unwrap();
        assert_eq!(vk, *pkp_3of4.verifying_key());
    }
}
