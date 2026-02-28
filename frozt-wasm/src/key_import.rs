use frost_core::{
    keys::{dkg, CoefficientCommitment, VerifiableSecretSharingCommitment},
    Ciphersuite, Field, Group,
};
use wasm_bindgen::prelude::*;

use crate::{js_obj, keygen, set_bytes, to_js_err, Identifier, J};

type F = <<J as Ciphersuite>::Group as Group>::Field;
type G = <J as Ciphersuite>::Group;

#[wasm_bindgen]
pub fn frozt_key_import_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    spending_key: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(JsError::new("invalid signers: need min >= 2 and max >= min"));
    }

    let id = Identifier::try_from(identifier).map_err(to_js_err)?;

    let constant_term = match spending_key {
        Some(ref sk) if !sk.is_empty() => {
            let sk_arr: &[u8; 32] = sk.as_slice()
                .try_into()
                .map_err(|_| JsError::new("spending key must be 32 bytes"))?;
            let sk_scalar = F::deserialize(sk_arr).map_err(to_js_err)?;
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

    let obj = js_obj();
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
