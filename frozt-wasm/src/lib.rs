mod codec;
mod cross_verify;
mod key_import;
mod keygen;
mod keyshare;
mod reshare;
mod sapling;
mod sign;
mod tree;
mod tx;

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

type Scalar = frost_core::Scalar<J>;

pub(crate) fn zeroize_scalar_vec(v: &mut Vec<Scalar>) {
    for s in v.iter_mut() {
        unsafe {
            let ptr = s as *mut Scalar as *mut u8;
            let len = std::mem::size_of::<Scalar>();
            for i in 0..len {
                std::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
    }
}
