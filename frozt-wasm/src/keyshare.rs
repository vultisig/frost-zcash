use std::collections::HashMap;
use std::sync::OnceLock;

use frost_core::keys::{KeyPackage, PublicKeyPackage};
use wasm_bindgen::prelude::*;

use crate::{to_js_err, Identifier, J};

static ID_LOOKUP: OnceLock<HashMap<Vec<u8>, u16>> = OnceLock::new();

fn get_id_lookup() -> &'static HashMap<Vec<u8>, u16> {
    ID_LOOKUP.get_or_init(|| {
        let mut map = HashMap::with_capacity(256);
        for i in 1..=256u16 {
            if let Ok(id) = Identifier::try_from(i) {
                map.insert(id.serialize(), i);
            }
        }
        map
    })
}

pub(crate) fn identifier_to_u16(id: &Identifier) -> Result<u16, JsError> {
    get_id_lookup()
        .get(&id.serialize())
        .copied()
        .ok_or_else(|| JsError::new("identifier not found in lookup"))
}

#[wasm_bindgen]
pub fn frozt_keypackage_identifier(key_package: &[u8]) -> Result<u16, JsError> {
    let kp = KeyPackage::<J>::deserialize(key_package).map_err(to_js_err)?;
    identifier_to_u16(kp.identifier())
}

#[wasm_bindgen]
pub fn frozt_pubkeypackage_verifying_key(pub_key_package: &[u8]) -> Result<Vec<u8>, JsError> {
    let pkp = PublicKeyPackage::<J>::deserialize(pub_key_package).map_err(to_js_err)?;
    let vk = pkp.verifying_key();
    let vk_bytes = vk.serialize().map_err(to_js_err)?;
    Ok(vk_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[test]
    fn test_identifier_roundtrip() {
        for id in 1..=10u16 {
            let ident = Identifier::try_from(id).unwrap();
            let decoded = identifier_to_u16(&ident).unwrap();
            assert_eq!(id, decoded);
        }
    }

    #[wasm_bindgen_test]
    fn test_identifier_roundtrip_wasm() {
        test_identifier_roundtrip();
    }
}
