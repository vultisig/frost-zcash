use std::collections::HashMap;
use std::sync::OnceLock;

use wasm_bindgen::prelude::*;

use crate::{to_js_err, Identifier};

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
pub fn frozt_encode_identifier(id: u16) -> Result<Vec<u8>, JsError> {
    let ident = Identifier::try_from(id).map_err(to_js_err)?;
    Ok(ident.serialize())
}

#[wasm_bindgen]
pub fn frozt_decode_identifier(id_bytes: &[u8]) -> Result<u16, JsError> {
    let ident = Identifier::deserialize(id_bytes).map_err(to_js_err)?;
    identifier_to_u16(&ident)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_identifier() {
        for id in 1..=10u16 {
            let encoded = frozt_encode_identifier(id).unwrap();
            let decoded = frozt_decode_identifier(&encoded).unwrap();
            assert_eq!(id, decoded);
        }
    }
}
