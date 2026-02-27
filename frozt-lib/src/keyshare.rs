use std::collections::HashMap;
use std::sync::OnceLock;

use frost_core::keys::KeyPackage;
use frost_core::keys::PublicKeyPackage;
use reddsa::frost::redjubjub::JubjubBlake2b512;

use crate::{
    bytes::*,
    errors::*,
};

type J = JubjubBlake2b512;
type Identifier = frost_core::Identifier<J>;

fn ser_err<E: std::fmt::Debug>(_: E) -> lib_error {
    lib_error::LIB_SERIALIZATION_ERROR
}

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

pub(crate) fn identifier_to_u16(id: &Identifier) -> Result<u16, lib_error> {
    get_id_lookup()
        .get(&id.serialize())
        .copied()
        .ok_or(lib_error::LIB_INVALID_IDENTIFIER)
}

#[no_mangle]
pub extern "C" fn frozt_encode_identifier(
    id: u16,
    out_bytes: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let ident = Identifier::try_from(id)
            .map_err(|_| lib_error::LIB_INVALID_IDENTIFIER)?;
        *out = tss_buffer::from_vec(ident.serialize());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frozt_decode_identifier(
    id_bytes: Option<&go_slice>,
    out_id: Option<&mut u16>,
) -> lib_error {
    with_error_handler(|| {
        let data = id_bytes.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_id.ok_or(lib_error::LIB_NULL_PTR)?;
        let ident = Identifier::deserialize(data.as_slice()).map_err(ser_err)?;
        *out = identifier_to_u16(&ident)?;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frozt_keypackage_identifier(
    key_package: Option<&go_slice>,
    out_id: Option<&mut u16>,
) -> lib_error {
    with_error_handler(|| {
        let kp_data = key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_id.ok_or(lib_error::LIB_NULL_PTR)?;

        let kp = KeyPackage::<J>::deserialize(kp_data.as_slice()).map_err(ser_err)?;
        *out = identifier_to_u16(kp.identifier())?;

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn frozt_pubkeypackage_verifying_key(
    pub_key_package: Option<&go_slice>,
    out_key: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let pkp_data = pub_key_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_key.ok_or(lib_error::LIB_NULL_PTR)?;

        let pkp = PublicKeyPackage::<J>::deserialize(pkp_data.as_slice()).map_err(ser_err)?;
        let vk = pkp.verifying_key();
        let vk_bytes = vk.serialize().map_err(ser_err)?;

        *out = tss_buffer::from_vec(vk_bytes);

        Ok(())
    })
}
