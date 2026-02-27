use std::collections::BTreeMap;

use frost_core::keys::dkg;
use wasm_bindgen::prelude::*;

use crate::{codec, js_obj, set_bytes, to_js_err, Identifier, J};

pub(crate) fn decode_r1_map(
    data: &[u8],
) -> Result<BTreeMap<Identifier, dkg::round1::Package<J>>, JsError> {
    codec::decode_map(
        data,
        |b| Identifier::deserialize(b).map_err(to_js_err),
        |b| dkg::round1::Package::<J>::deserialize(b).map_err(to_js_err),
    )
}

pub(crate) fn encode_r2_map(
    map: &BTreeMap<Identifier, dkg::round2::Package<J>>,
) -> Result<Vec<u8>, JsError> {
    codec::encode_map(
        map,
        |id| Ok(id.serialize()),
        |pkg| pkg.serialize().map_err(to_js_err),
    )
}

pub(crate) fn decode_r2_map(
    data: &[u8],
) -> Result<BTreeMap<Identifier, dkg::round2::Package<J>>, JsError> {
    codec::decode_map(
        data,
        |b| Identifier::deserialize(b).map_err(to_js_err),
        |b| dkg::round2::Package::<J>::deserialize(b).map_err(to_js_err),
    )
}

#[wasm_bindgen]
pub fn frozt_dkg_part1(
    id: u16,
    max_signers: u16,
    min_signers: u16,
) -> Result<JsValue, JsError> {
    let ident = Identifier::try_from(id).map_err(to_js_err)?;
    let (secret, package) =
        dkg::part1::<J, _>(ident, max_signers, min_signers, rand::thread_rng())
            .map_err(to_js_err)?;

    let secret_bytes = secret.serialize().map_err(to_js_err)?;
    let pkg_bytes = package.serialize().map_err(to_js_err)?;

    let obj = js_obj();
    set_bytes(&obj, "secret", &secret_bytes);
    set_bytes(&obj, "package", &pkg_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frozt_dkg_part2(
    secret: &[u8],
    round1_packages: &[u8],
) -> Result<JsValue, JsError> {
    let secret_pkg =
        dkg::round1::SecretPackage::<J>::deserialize(secret).map_err(to_js_err)?;
    let r1_pkgs = decode_r1_map(round1_packages)?;

    let (secret2, r2_pkgs) = dkg::part2(secret_pkg, &r1_pkgs).map_err(to_js_err)?;

    let secret2_bytes = secret2.serialize().map_err(to_js_err)?;
    let r2_bytes = encode_r2_map(&r2_pkgs)?;

    let obj = js_obj();
    set_bytes(&obj, "secret", &secret2_bytes);
    set_bytes(&obj, "packages", &r2_bytes);
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn frozt_dkg_part3(
    secret: &[u8],
    round1_packages: &[u8],
    round2_packages: &[u8],
) -> Result<JsValue, JsError> {
    let secret_pkg =
        dkg::round2::SecretPackage::<J>::deserialize(secret).map_err(to_js_err)?;
    let r1_pkgs = decode_r1_map(round1_packages)?;
    let r2_pkgs = decode_r2_map(round2_packages)?;

    let (key_package, pub_key_package) =
        dkg::part3(&secret_pkg, &r1_pkgs, &r2_pkgs).map_err(to_js_err)?;

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
    use crate::keyshare::identifier_to_u16;

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

    pub(crate) fn decode_id_map(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut pos = 0;
        let count =
            u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let mut entries = Vec::new();
        for _ in 0..count {
            let klen =
                u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let id = Identifier::deserialize(&data[pos..pos + klen]).unwrap();
            pos += klen;
            let vlen =
                u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let v = data[pos..pos + vlen].to_vec();
            pos += vlen;
            let id_u16 = identifier_to_u16(&id).unwrap();
            entries.push((id_u16, v));
        }
        entries
    }

    pub fn run_dkg_native(n: u16, t: u16) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut secrets1 = Vec::new();
        let mut packages1 = Vec::new();

        for i in 1..=n {
            let ident = Identifier::try_from(i).unwrap();
            let (secret, package) =
                dkg::part1::<J, _>(ident, n, t, rand::thread_rng()).unwrap();
            let secret_bytes = secret.serialize().unwrap();
            let pkg_bytes = package.serialize().unwrap();
            secrets1.push(secret_bytes);
            packages1.push((i, pkg_bytes));
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

            let r1_map = encode_id_map(&others);

            let secret_pkg =
                dkg::round1::SecretPackage::<J>::deserialize(&secrets1[i]).unwrap();
            let r1_pkgs = decode_r1_map(&r1_map).unwrap();
            let (secret2, r2_pkgs) = dkg::part2(secret_pkg, &r1_pkgs).unwrap();

            let secret2_bytes = secret2.serialize().unwrap();
            let r2_bytes = encode_r2_map(&r2_pkgs).unwrap();
            let r2_decoded = decode_id_map(&r2_bytes);

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

            let r1_map = encode_id_map(&r1_others);
            let r2_map = encode_id_map(&r2_for_me);

            let secret_pkg =
                dkg::round2::SecretPackage::<J>::deserialize(&secrets2[i]).unwrap();
            let r1_pkgs = decode_r1_map(&r1_map).unwrap();
            let r2_pkgs = decode_r2_map(&r2_map).unwrap();
            let (key_package, pub_key_package) =
                dkg::part3(&secret_pkg, &r1_pkgs, &r2_pkgs).unwrap();

            let kp_bytes = key_package.serialize().unwrap();
            let pkp_bytes = pub_key_package.serialize().unwrap();
            results.push((kp_bytes, pkp_bytes));
        }

        results
    }

    #[test]
    fn test_dkg_2x3() {
        let results = run_dkg_native(3, 2);
        assert_eq!(results.len(), 3);

        let pkp0 =
            frost_core::keys::PublicKeyPackage::<J>::deserialize(&results[0].1)
                .unwrap();
        let pkp1 =
            frost_core::keys::PublicKeyPackage::<J>::deserialize(&results[1].1)
                .unwrap();
        let pkp2 =
            frost_core::keys::PublicKeyPackage::<J>::deserialize(&results[2].1)
                .unwrap();

        assert_eq!(pkp0.verifying_key(), pkp1.verifying_key());
        assert_eq!(pkp1.verifying_key(), pkp2.verifying_key());
    }
}
