use std::collections::BTreeMap;

use crate::errors::lib_error;

pub fn encode_map<K, V, FK, FV>(
    map: &BTreeMap<K, V>,
    encode_key: FK,
    encode_val: FV,
) -> Result<Vec<u8>, lib_error>
where
    K: Ord,
    FK: Fn(&K) -> Result<Vec<u8>, lib_error>,
    FV: Fn(&V) -> Result<Vec<u8>, lib_error>,
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
) -> Result<BTreeMap<K, V>, lib_error>
where
    K: Ord,
    FK: Fn(&[u8]) -> Result<K, lib_error>,
    FV: Fn(&[u8]) -> Result<V, lib_error>,
{
    let mut pos = 0;
    let count = read_u32(data, &mut pos)? as usize;
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let klen = read_u32(data, &mut pos)? as usize;
        if pos + klen > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let k = decode_key(&data[pos..pos + klen])?;
        pos += klen;
        let vlen = read_u32(data, &mut pos)? as usize;
        if pos + vlen > data.len() {
            return Err(lib_error::LIB_SERIALIZATION_ERROR);
        }
        let v = decode_val(&data[pos..pos + vlen])?;
        pos += vlen;
        map.insert(k, v);
    }
    Ok(map)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, lib_error> {
    if *pos + 4 > data.len() {
        return Err(lib_error::LIB_SERIALIZATION_ERROR);
    }
    let val = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}
