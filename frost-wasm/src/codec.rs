use std::collections::BTreeMap;

use wasm_bindgen::prelude::*;

pub fn encode_map<K, V, FK, FV>(
    map: &BTreeMap<K, V>,
    encode_key: FK,
    encode_val: FV,
) -> Result<Vec<u8>, JsError>
where
    K: Ord,
    FK: Fn(&K) -> Result<Vec<u8>, JsError>,
    FV: Fn(&V) -> Result<Vec<u8>, JsError>,
{
    let mut buf = Vec::new();
    buf.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (k, v) in map {
        let kb = encode_key(k)?;
        let vb = encode_val(v)?;
        buf.extend_from_slice(&(kb.len() as u32).to_le_bytes());
        buf.extend_from_slice(&kb);
        buf.extend_from_slice(&(vb.len() as u32).to_le_bytes());
        buf.extend_from_slice(&vb);
    }
    Ok(buf)
}

pub fn decode_map<K, V, FK, FV>(
    data: &[u8],
    decode_key: FK,
    decode_val: FV,
) -> Result<BTreeMap<K, V>, JsError>
where
    K: Ord,
    FK: Fn(&[u8]) -> Result<K, JsError>,
    FV: Fn(&[u8]) -> Result<V, JsError>,
{
    let mut pos = 0;
    let count = read_u32(data, &mut pos)? as usize;
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let klen = read_u32(data, &mut pos)? as usize;
        if pos + klen > data.len() {
            return Err(JsError::new("codec: buffer underflow reading key"));
        }
        let k = decode_key(&data[pos..pos + klen])?;
        pos += klen;
        let vlen = read_u32(data, &mut pos)? as usize;
        if pos + vlen > data.len() {
            return Err(JsError::new("codec: buffer underflow reading value"));
        }
        let v = decode_val(&data[pos..pos + vlen])?;
        pos += vlen;
        map.insert(k, v);
    }
    Ok(map)
}

pub(crate) fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, JsError> {
    if *pos + 4 > data.len() {
        return Err(JsError::new("codec: buffer underflow reading u32"));
    }
    let val = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}

#[wasm_bindgen(js_name = "encode_map")]
pub fn wasm_encode_map(entries: JsValue) -> Result<Vec<u8>, JsError> {
    let arr = js_sys::Array::from(&entries);
    let len = arr.length();
    let mut buf = Vec::new();
    buf.extend_from_slice(&(len as u32).to_le_bytes());
    for i in 0..len {
        let entry = arr.get(i);
        let id = js_sys::Reflect::get(&entry, &"id".into())
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        let value = js_sys::Reflect::get(&entry, &"value".into())
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        let id_bytes = js_sys::Uint8Array::from(id).to_vec();
        let val_bytes = js_sys::Uint8Array::from(value).to_vec();
        buf.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&id_bytes);
        buf.extend_from_slice(&(val_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&val_bytes);
    }
    Ok(buf)
}

#[wasm_bindgen(js_name = "decode_map")]
pub fn wasm_decode_map(data: &[u8]) -> Result<JsValue, JsError> {
    let arr = js_sys::Array::new();
    let mut pos = 0;
    let count = read_u32(data, &mut pos)?;
    for _ in 0..count {
        let klen = read_u32(data, &mut pos)? as usize;
        if pos + klen > data.len() {
            return Err(JsError::new("decode_map: buffer underflow"));
        }
        let key = &data[pos..pos + klen];
        pos += klen;
        let vlen = read_u32(data, &mut pos)? as usize;
        if pos + vlen > data.len() {
            return Err(JsError::new("decode_map: buffer underflow"));
        }
        let val = &data[pos..pos + vlen];
        pos += vlen;
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &"id".into(),
            &js_sys::Uint8Array::from(key),
        )
        .unwrap();
        js_sys::Reflect::set(
            &obj,
            &"value".into(),
            &js_sys::Uint8Array::from(val),
        )
        .unwrap();
        arr.push(&obj);
    }
    Ok(arr.into())
}
