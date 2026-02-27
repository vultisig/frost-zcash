use std::collections::BTreeMap;

use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::round1::{SigningCommitments, SigningNonces};
use frost_core::round2::SignatureShare;
use frost_core::SigningPackage;
use frost_rerandomized::{Randomizer, RandomizedParams};
use wasm_bindgen::prelude::*;

use crate::{codec, js_obj, set_bytes, to_js_err, Identifier, J};

fn decode_commitments_map(
    data: &[u8],
) -> Result<BTreeMap<Identifier, SigningCommitments<J>>, JsError> {
    codec::decode_map(
        data,
        |b| Identifier::deserialize(b).map_err(to_js_err),
        |b| SigningCommitments::<J>::deserialize(b).map_err(to_js_err),
    )
}

fn decode_shares_map(
    data: &[u8],
) -> Result<BTreeMap<Identifier, SignatureShare<J>>, JsError> {
    codec::decode_map(
        data,
        |b| Identifier::deserialize(b).map_err(to_js_err),
        |b| SignatureShare::<J>::deserialize(b).map_err(to_js_err),
    )
}

#[wasm_bindgen]
pub fn frost_sign_commit(key_package: &[u8]) -> Result<JsValue, JsError> {
    let kp = KeyPackage::<J>::deserialize(key_package).map_err(to_js_err)?;

    let mut rng = rand::thread_rng();
    let (nonces, commitments) =
        frost_core::round1::commit(kp.signing_share(), &mut rng);

    let nonces_bytes = nonces.serialize().map_err(to_js_err)?;
    let commitments_bytes = commitments.serialize().map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "nonces", &nonces_bytes);
    set_bytes(&obj, "commitments", &commitments_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frost_sign_new_package(
    message: &[u8],
    commitments: &[u8],
    pub_key_package: &[u8],
) -> Result<JsValue, JsError> {
    let commitments_map = decode_commitments_map(commitments)?;
    let pkp =
        PublicKeyPackage::<J>::deserialize(pub_key_package).map_err(to_js_err)?;

    let signing_package = SigningPackage::<J>::new(commitments_map, message);

    let randomized_params = RandomizedParams::<J>::new(
        pkp.verifying_key(),
        &signing_package,
        rand::thread_rng(),
    )
    .map_err(to_js_err)?;

    let randomizer_bytes = randomized_params.randomizer().serialize();
    let sp_bytes = signing_package.serialize().map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "signingPackage", &sp_bytes);
    set_bytes(&obj, "randomizer", &randomizer_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frost_sign(
    signing_package: &[u8],
    nonces: &[u8],
    key_package: &[u8],
    randomizer: &[u8],
) -> Result<Vec<u8>, JsError> {
    let sp =
        SigningPackage::<J>::deserialize(signing_package).map_err(to_js_err)?;
    let nonces = SigningNonces::<J>::deserialize(nonces).map_err(to_js_err)?;
    let kp = KeyPackage::<J>::deserialize(key_package).map_err(to_js_err)?;
    let randomizer =
        Randomizer::<J>::deserialize(randomizer).map_err(to_js_err)?;

    let share = frost_rerandomized::sign(&sp, &nonces, &kp, randomizer)
        .map_err(to_js_err)?;

    Ok(share.serialize())
}

#[wasm_bindgen]
pub fn frost_sign_aggregate(
    signing_package: &[u8],
    shares: &[u8],
    pub_key_package: &[u8],
    randomizer: &[u8],
) -> Result<Vec<u8>, JsError> {
    let sp =
        SigningPackage::<J>::deserialize(signing_package).map_err(to_js_err)?;
    let shares_map = decode_shares_map(shares)?;
    let pkp =
        PublicKeyPackage::<J>::deserialize(pub_key_package).map_err(to_js_err)?;
    let randomizer =
        Randomizer::<J>::deserialize(randomizer).map_err(to_js_err)?;

    let randomized_params =
        RandomizedParams::<J>::from_randomizer(pkp.verifying_key(), randomizer);

    let signature =
        frost_rerandomized::aggregate(&sp, &shares_map, &pkp, &randomized_params)
            .map_err(to_js_err)?;

    let sig_bytes = signature.serialize().map_err(to_js_err)?;
    Ok(sig_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::tests::run_dkg_native;

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

    #[test]
    fn test_sign_2x3() {
        let dkg_results = run_dkg_native(3, 2);
        let signer_indices = [0usize, 1];
        let signer_ids: Vec<u16> =
            signer_indices.iter().map(|i| (*i + 1) as u16).collect();

        let mut nonce_list = Vec::new();
        let mut commitments_entries: Vec<(u16, Vec<u8>)> = Vec::new();

        for &idx in &signer_indices {
            let kp = &dkg_results[idx].0;
            let kp_obj = KeyPackage::<J>::deserialize(kp).unwrap();

            let mut rng = rand::thread_rng();
            let (nonces, commitments) =
                frost_core::round1::commit(kp_obj.signing_share(), &mut rng);

            let nonces_bytes = nonces.serialize().unwrap();
            let commitments_bytes = commitments.serialize().unwrap();

            nonce_list.push(nonces_bytes);
            commitments_entries
                .push((signer_ids[commitments_entries.len()], commitments_bytes));
        }

        let commitments_map = encode_id_map(&commitments_entries);
        let pkp_bytes = &dkg_results[signer_indices[0]].1;
        let pkp = PublicKeyPackage::<J>::deserialize(pkp_bytes).unwrap();

        let message = b"test message for frost signing";

        let commitments_decoded = decode_commitments_map(&commitments_map).unwrap();
        let signing_package =
            SigningPackage::<J>::new(commitments_decoded, message.as_ref());

        let randomized_params = RandomizedParams::<J>::new(
            pkp.verifying_key(),
            &signing_package,
            rand::thread_rng(),
        )
        .unwrap();

        let randomizer_bytes = randomized_params.randomizer().serialize();
        let sp_bytes = signing_package.serialize().unwrap();

        let mut share_entries: Vec<(u16, Vec<u8>)> = Vec::new();

        for (i, &idx) in signer_indices.iter().enumerate() {
            let sp = SigningPackage::<J>::deserialize(&sp_bytes).unwrap();
            let nonces =
                SigningNonces::<J>::deserialize(&nonce_list[i]).unwrap();
            let kp = KeyPackage::<J>::deserialize(&dkg_results[idx].0).unwrap();
            let randomizer =
                Randomizer::<J>::deserialize(&randomizer_bytes).unwrap();

            let share =
                frost_rerandomized::sign(&sp, &nonces, &kp, randomizer).unwrap();

            share_entries.push((signer_ids[i], share.serialize()));
        }

        let shares_map = encode_id_map(&share_entries);
        let shares_decoded = decode_shares_map(&shares_map).unwrap();
        let sp = SigningPackage::<J>::deserialize(&sp_bytes).unwrap();
        let randomizer =
            Randomizer::<J>::deserialize(&randomizer_bytes).unwrap();
        let randomized_params =
            RandomizedParams::<J>::from_randomizer(pkp.verifying_key(), randomizer);

        let signature = frost_rerandomized::aggregate(
            &sp,
            &shares_decoded,
            &pkp,
            &randomized_params,
        )
        .unwrap();

        let sig_bytes = signature.serialize().unwrap();
        assert!(!sig_bytes.is_empty());
    }
}
