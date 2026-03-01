use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use sapling_crypto::{Anchor, Node, NOTE_COMMITMENT_TREE_DEPTH};
use std::io::{self, Read, Write};

use crate::{
    bytes::*,
    errors::*,
    handle::Handle,
};

pub type SaplingTree = CommitmentTree<Node, NOTE_COMMITMENT_TREE_DEPTH>;
pub type SaplingWitness = IncrementalWitness<Node, NOTE_COMMITMENT_TREE_DEPTH>;

fn read_node<R: Read>(mut reader: R) -> io::Result<Node> {
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf)?;
    let ct = Node::from_bytes(buf);
    if ct.is_none().into() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid node"));
    }
    Ok(ct.unwrap())
}

fn read_optional_node<R: Read>(mut reader: R) -> io::Result<Option<Node>> {
    let flag = reader.read_u8()?;
    if flag == 0 {
        Ok(None)
    } else {
        Ok(Some(read_node(&mut reader)?))
    }
}

fn write_optional_node<W: Write>(writer: &mut W, node: &Option<Node>) -> io::Result<()> {
    match node {
        Some(n) => {
            writer.write_all(&[1])?;
            writer.write_all(&n.to_bytes())?;
        }
        None => writer.write_all(&[0])?,
    }
    Ok(())
}

fn read_compact_size<R: Read>(mut reader: R) -> io::Result<usize> {
    let first = reader.read_u8()?;
    match first {
        0..=252 => Ok(first as usize),
        253 => Ok(reader.read_u16::<LittleEndian>()? as usize),
        254 => Ok(reader.read_u32::<LittleEndian>()? as usize),
        255 => Ok(reader.read_u64::<LittleEndian>()? as usize),
    }
}

fn write_compact_size<W: Write>(mut writer: W, val: usize) -> io::Result<()> {
    if val < 253 {
        writer.write_u8(val as u8)
    } else if val <= 0xFFFF {
        writer.write_u8(253)?;
        writer.write_u16::<LittleEndian>(val as u16)
    } else if val <= 0xFFFFFFFF {
        writer.write_u8(254)?;
        writer.write_u32::<LittleEndian>(val as u32)
    } else {
        writer.write_u8(255)?;
        writer.write_u64::<LittleEndian>(val as u64)
    }
}

pub fn read_commitment_tree_data<R: Read>(mut reader: R) -> io::Result<SaplingTree> {
    let left = read_optional_node(&mut reader)?;
    let right = read_optional_node(&mut reader)?;

    let parent_count = read_compact_size(&mut reader)?;
    if parent_count > NOTE_COMMITMENT_TREE_DEPTH as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "parent_count exceeds tree depth"));
    }
    let mut parents = Vec::with_capacity(parent_count);
    for _ in 0..parent_count {
        parents.push(read_optional_node(&mut reader)?);
    }

    CommitmentTree::from_parts(left, right, parents).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid commitment tree")
    })
}

pub fn write_commitment_tree_data<W: Write>(tree: &SaplingTree, mut writer: W) -> io::Result<()> {
    write_optional_node(&mut writer, tree.left())?;
    write_optional_node(&mut writer, tree.right())?;
    let parents = tree.parents();
    write_compact_size(&mut writer, parents.len())?;
    for parent in parents {
        write_optional_node(&mut writer, parent)?;
    }
    Ok(())
}

fn parse_cmu(data: &[u8]) -> Result<Node, lib_error> {
    if data.len() != 32 {
        return Err(lib_error::LIB_INVALID_BUFFER_SIZE);
    }
    let bytes: [u8; 32] = data[..32].try_into().unwrap();
    let ct = Node::from_bytes(bytes);
    if ct.is_none().into() {
        return Err(lib_error::LIB_SAPLING_ERROR);
    }
    Ok(ct.unwrap())
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_tree_from_state(
    tree_state_hex: Option<&go_slice>,
    out_tree: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let hex_data = tree_state_hex.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_tree.ok_or(lib_error::LIB_NULL_PTR)?;

        let hex_str = std::str::from_utf8(hex_data.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        let bytes = hex::decode(hex_str)
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let tree: SaplingTree = read_commitment_tree_data(&bytes[..])
            .map_err(|_| lib_error::LIB_SAPLING_ERROR)?;

        *out = Handle::allocate(tree)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_tree_append(
    tree: Handle,
    cmu: Option<&go_slice>,
) -> lib_error {
    with_error_handler(|| {
        let cmu_data = cmu.ok_or(lib_error::LIB_NULL_PTR)?;
        let node = parse_cmu(cmu_data.as_slice())?;

        let mut guard = tree.get::<SaplingTree>()?;
        guard.append(node).map_err(|_| lib_error::LIB_SAPLING_ERROR)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_tree_witness(
    tree: Handle,
    out_witness: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_witness.ok_or(lib_error::LIB_NULL_PTR)?;

        let guard = tree.get::<SaplingTree>()?;
        let witness = SaplingWitness::from_tree(guard.clone())
            .ok_or(lib_error::LIB_SAPLING_ERROR)?;

        *out = Handle::allocate(witness)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_witness_append(
    witness: Handle,
    cmu: Option<&go_slice>,
) -> lib_error {
    with_error_handler(|| {
        let cmu_data = cmu.ok_or(lib_error::LIB_NULL_PTR)?;
        let node = parse_cmu(cmu_data.as_slice())?;

        let mut guard = witness.get::<SaplingWitness>()?;
        guard.append(node).map_err(|_| lib_error::LIB_SAPLING_ERROR)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_witness_root(
    witness: Handle,
    out_anchor: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_anchor.ok_or(lib_error::LIB_NULL_PTR)?;

        let guard = witness.get::<SaplingWitness>()?;
        let root = guard.root();
        let anchor = Anchor::from(root);

        *out = tss_buffer::from_vec(anchor.to_bytes().to_vec());
        Ok(())
    })
}

pub fn serialize_witness(witness: &SaplingWitness) -> Result<Vec<u8>, lib_error> {
    let mut buf = Vec::new();
    write_commitment_tree_data(witness.tree(), &mut buf)
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

    let filled = witness.filled();
    write_compact_size(&mut buf, filled.len())
        .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
    for node in filled {
        buf.extend_from_slice(&node.to_bytes());
    }

    match witness.cursor() {
        Some(cursor) => {
            buf.push(1);
            write_commitment_tree_data(cursor, &mut buf)
                .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        }
        None => buf.push(0),
    }

    Ok(buf)
}

pub fn deserialize_witness(data: &[u8]) -> Result<SaplingWitness, lib_error> {
    let mut reader = std::io::Cursor::new(data);

    let tree: SaplingTree = read_commitment_tree_data(&mut reader)
        .map_err(|_| lib_error::LIB_SAPLING_ERROR)?;

    let filled_count = read_compact_size(&mut reader)
        .map_err(|_| lib_error::LIB_SAPLING_ERROR)?;
    if filled_count > NOTE_COMMITMENT_TREE_DEPTH as usize {
        return Err(lib_error::LIB_SAPLING_ERROR);
    }
    let mut filled = Vec::with_capacity(filled_count);
    for _ in 0..filled_count {
        filled.push(read_node(&mut reader)
            .map_err(|_| lib_error::LIB_SAPLING_ERROR)?);
    }

    let cursor_flag = reader.read_u8()
        .map_err(|_| lib_error::LIB_SAPLING_ERROR)?;
    let cursor = if cursor_flag != 0 {
        Some(read_commitment_tree_data(&mut reader)
            .map_err(|_| lib_error::LIB_SAPLING_ERROR)?)
    } else {
        None
    };

    SaplingWitness::from_parts(tree, filled, cursor)
        .ok_or(lib_error::LIB_SAPLING_ERROR)
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_witness_serialize(
    witness: Handle,
    out_data: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let out = out_data.ok_or(lib_error::LIB_NULL_PTR)?;
        let guard = witness.get::<SaplingWitness>()?;
        let buf = serialize_witness(&guard)?;
        *out = tss_buffer::from_vec(buf);
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_witness_deserialize(
    data: Option<&go_slice>,
    out_witness: Option<&mut Handle>,
) -> lib_error {
    with_error_handler(|| {
        let wit_data = data.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_witness.ok_or(lib_error::LIB_NULL_PTR)?;

        let witness = deserialize_witness(wit_data.as_slice())?;
        *out = Handle::allocate(witness)?;
        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_sapling_tree_size(
    tree_state_hex: Option<&go_slice>,
    out_size: Option<&mut u64>,
) -> lib_error {
    with_error_handler(|| {
        let hex_data = tree_state_hex.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_size.ok_or(lib_error::LIB_NULL_PTR)?;

        let hex_str = std::str::from_utf8(hex_data.as_slice())
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;
        let bytes = hex::decode(hex_str)
            .map_err(|_| lib_error::LIB_SERIALIZATION_ERROR)?;

        let tree: SaplingTree = read_commitment_tree_data(&bytes[..])
            .map_err(|_| lib_error::LIB_SAPLING_ERROR)?;

        *out = tree.size() as u64;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::Hashable;

    #[test]
    fn test_empty_tree_roundtrip() {
        let tree: SaplingTree = SaplingTree::empty();
        let mut buf = Vec::new();
        write_commitment_tree_data(&tree, &mut buf).unwrap();
        let tree2 = read_commitment_tree_data(&buf[..]).unwrap();
        assert_eq!(tree.root(), tree2.root());
    }

    #[test]
    fn test_tree_append_and_witness() {
        let mut tree: SaplingTree = SaplingTree::empty();
        let node = Node::empty_leaf();
        tree.append(node).unwrap();
        let witness = SaplingWitness::from_tree(tree.clone()).unwrap();
        let root = witness.root();
        let tree_root = tree.root();
        assert_eq!(root, tree_root);
    }

    #[test]
    fn test_witness_serialize_roundtrip() {
        let mut tree: SaplingTree = SaplingTree::empty();
        for i in 0u8..10 {
            let mut bytes = [0u8; 32];
            bytes[0] = i + 1;
            let node = Node::from_bytes(bytes);
            if let Some(n) = Option::from(node) {
                tree.append(n).unwrap();
            }
        }

        let witness = SaplingWitness::from_tree(tree).unwrap();
        let buf = serialize_witness(&witness).unwrap();
        let witness2 = deserialize_witness(&buf).unwrap();

        assert_eq!(witness.root(), witness2.root());
    }
}
