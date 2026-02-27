mod address;
mod codec;
mod keygen;
mod keyshare;
mod reshare;
mod sign;

use reddsa::frost::redjubjub::JubjubBlake2b512;

pub(crate) type J = JubjubBlake2b512;
pub(crate) type Identifier = frost_core::Identifier<J>;

pub(crate) fn to_js_err<E: std::fmt::Debug>(e: E) -> wasm_bindgen::JsError {
    wasm_bindgen::JsError::new(&format!("{:?}", e))
}

pub(crate) fn js_obj() -> js_sys::Object {
    js_sys::Object::new()
}

pub(crate) fn set_bytes(obj: &js_sys::Object, key: &str, data: &[u8]) {
    let arr = js_sys::Uint8Array::from(data);
    js_sys::Reflect::set(obj, &wasm_bindgen::JsValue::from_str(key), &arr).unwrap();
}
