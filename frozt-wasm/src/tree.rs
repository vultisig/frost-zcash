use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use sapling_crypto::{Anchor, Node, NOTE_COMMITMENT_TREE_DEPTH};
use std::io::{self, Read, Write};
use wasm_bindgen::prelude::*;

type SaplingTree = CommitmentTree<Node, NOTE_COMMITMENT_TREE_DEPTH>;
type SaplingWitness = IncrementalWitness<Node, NOTE_COMMITMENT_TREE_DEPTH>;

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

fn read_commitment_tree_data<R: Read>(mut reader: R) -> io::Result<SaplingTree> {
    let left = read_optional_node(&mut reader)?;
    let right = read_optional_node(&mut reader)?;

    let parent_count = read_compact_size(&mut reader)?;
    let mut parents = Vec::with_capacity(parent_count);
    for _ in 0..parent_count {
        parents.push(read_optional_node(&mut reader)?);
    }

    CommitmentTree::from_parts(left, right, parents).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid commitment tree")
    })
}

fn write_commitment_tree_data<W: Write>(tree: &SaplingTree, mut writer: W) -> io::Result<()> {
    write_optional_node(&mut writer, tree.left())?;
    write_optional_node(&mut writer, tree.right())?;
    let parents = tree.parents();
    write_compact_size(&mut writer, parents.len())?;
    for parent in parents {
        write_optional_node(&mut writer, parent)?;
    }
    Ok(())
}

fn parse_node(cmu: &[u8]) -> Result<Node, JsError> {
    if cmu.len() != 32 {
        return Err(JsError::new("cmu must be 32 bytes"));
    }
    let bytes: [u8; 32] = cmu[..32].try_into().unwrap();
    let ct = Node::from_bytes(bytes);
    if ct.is_none().into() {
        return Err(JsError::new("invalid sapling node"));
    }
    Ok(ct.unwrap())
}

fn serialize_witness(witness: &SaplingWitness) -> Result<Vec<u8>, JsError> {
    let mut buf = Vec::new();
    write_commitment_tree_data(witness.tree(), &mut buf)
        .map_err(|e| JsError::new(&format!("serialize tree: {}", e)))?;

    let filled = witness.filled();
    write_compact_size(&mut buf, filled.len())
        .map_err(|e| JsError::new(&format!("serialize filled count: {}", e)))?;
    for node in filled {
        buf.extend_from_slice(&node.to_bytes());
    }

    match witness.cursor() {
        Some(cursor) => {
            buf.push(1);
            write_commitment_tree_data(cursor, &mut buf)
                .map_err(|e| JsError::new(&format!("serialize cursor: {}", e)))?;
        }
        None => buf.push(0),
    }

    Ok(buf)
}

fn deserialize_witness(data: &[u8]) -> Result<SaplingWitness, JsError> {
    let mut reader = std::io::Cursor::new(data);

    let tree: SaplingTree = read_commitment_tree_data(&mut reader)
        .map_err(|e| JsError::new(&format!("deserialize tree: {}", e)))?;

    let filled_count = read_compact_size(&mut reader)
        .map_err(|e| JsError::new(&format!("deserialize filled count: {}", e)))?;
    let mut filled = Vec::with_capacity(filled_count);
    for _ in 0..filled_count {
        let node = read_node(&mut reader)
            .map_err(|e| JsError::new(&format!("deserialize filled node: {}", e)))?;
        filled.push(node);
    }

    let cursor_flag = reader.read_u8()
        .map_err(|e| JsError::new(&format!("deserialize cursor flag: {}", e)))?;
    let cursor = if cursor_flag != 0 {
        let c = read_commitment_tree_data(&mut reader)
            .map_err(|e| JsError::new(&format!("deserialize cursor: {}", e)))?;
        Some(c)
    } else {
        None
    };

    SaplingWitness::from_parts(tree, filled, cursor)
        .ok_or_else(|| JsError::new("invalid witness parts"))
}

#[wasm_bindgen]
pub struct WasmSaplingTree {
    inner: SaplingTree,
}

#[wasm_bindgen]
impl WasmSaplingTree {
    #[wasm_bindgen(js_name = "fromHexState")]
    pub fn from_hex_state(hex_state: &str) -> Result<WasmSaplingTree, JsError> {
        let bytes = hex::decode(hex_state)
            .map_err(|e| JsError::new(&format!("hex decode: {}", e)))?;
        let tree = read_commitment_tree_data(&bytes[..])
            .map_err(|e| JsError::new(&format!("parse tree: {}", e)))?;
        Ok(WasmSaplingTree { inner: tree })
    }

    pub fn append(&mut self, cmu: &[u8]) -> Result<(), JsError> {
        let node = parse_node(cmu)?;
        self.inner.append(node)
            .map_err(|_| JsError::new("tree append failed: tree is full"))
    }

    pub fn witness(&self) -> Result<WasmSaplingWitness, JsError> {
        let witness = SaplingWitness::from_tree(self.inner.clone())
            .ok_or_else(|| JsError::new("cannot create witness from empty tree"))?;
        Ok(WasmSaplingWitness { inner: witness })
    }
}

#[wasm_bindgen]
pub struct WasmSaplingWitness {
    inner: SaplingWitness,
}

#[wasm_bindgen]
impl WasmSaplingWitness {
    pub fn append(&mut self, cmu: &[u8]) -> Result<(), JsError> {
        let node = parse_node(cmu)?;
        self.inner.append(node)
            .map_err(|_| JsError::new("witness append failed"))
    }

    pub fn root(&self) -> Result<Vec<u8>, JsError> {
        let root = self.inner.root();
        let anchor = Anchor::from(root);
        Ok(anchor.to_bytes().to_vec())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        serialize_witness(&self.inner)
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(data: &[u8]) -> Result<WasmSaplingWitness, JsError> {
        let witness = deserialize_witness(data)?;
        Ok(WasmSaplingWitness { inner: witness })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[test]
    fn test_tree_from_empty_state() {
        let tree = WasmSaplingTree::from_hex_state("000000").unwrap();
        assert!(tree.inner.left().is_none());
    }

    #[test]
    fn test_tree_append_and_witness() {
        let mut tree = WasmSaplingTree::from_hex_state("000000").unwrap();

        let mut cmu = [0u8; 32];
        cmu[0] = 1;
        tree.append(&cmu).unwrap();

        let witness = tree.witness().unwrap();
        let root = witness.root().unwrap();
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_witness_serialize_roundtrip() {
        let mut tree = WasmSaplingTree::from_hex_state("000000").unwrap();

        for i in 1u8..=5 {
            let mut cmu = [0u8; 32];
            cmu[0] = i;
            tree.append(&cmu).unwrap();
        }

        let witness = tree.witness().unwrap();
        let root1 = witness.root().unwrap();

        let serialized = witness.serialize().unwrap();
        assert!(!serialized.is_empty());

        let witness2 = WasmSaplingWitness::from_bytes(&serialized).unwrap();
        let root2 = witness2.root().unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_witness_append_changes_root() {
        let mut tree = WasmSaplingTree::from_hex_state("000000").unwrap();

        let mut cmu1 = [0u8; 32];
        cmu1[0] = 1;
        tree.append(&cmu1).unwrap();

        let mut witness = tree.witness().unwrap();
        let root_before = witness.root().unwrap();

        let mut cmu2 = [0u8; 32];
        cmu2[0] = 2;
        tree.append(&cmu2).unwrap();
        witness.append(&cmu2).unwrap();

        let root_after = witness.root().unwrap();
        assert_ne!(root_before, root_after);
    }

    #[wasm_bindgen_test]
    fn test_tree_from_empty_state_wasm() {
        test_tree_from_empty_state();
    }

    #[wasm_bindgen_test]
    fn test_tree_append_and_witness_wasm() {
        test_tree_append_and_witness();
    }

    #[wasm_bindgen_test]
    fn test_witness_serialize_roundtrip_wasm() {
        test_witness_serialize_roundtrip();
    }

    #[wasm_bindgen_test]
    fn test_witness_append_changes_root_wasm() {
        test_witness_append_changes_root();
    }
}
