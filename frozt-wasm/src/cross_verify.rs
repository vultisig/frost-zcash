#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::key_import::tests::run_key_import_native;
    use crate::keyshare::identifier_to_u16;
    use crate::sapling::frozt_sapling_derive_keys;
    use crate::tree::{WasmSaplingTree, WasmSaplingWitness};
    use crate::Identifier;

    const ABANDON_SEED: &str =
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
         9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    const EXPECTED_ADDRESS: &str =
        "zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta";

    fn abandon_seed() -> Vec<u8> {
        hex::decode(ABANDON_SEED).unwrap()
    }

    #[test]
    fn test_abandon_mnemonic_address() {
        let seed = abandon_seed();
        let import = run_key_import_native(3, 2, &seed, 0);
        let pkp = &import.results[0].1;
        let keys = frozt_sapling_derive_keys(pkp, &import.extras).unwrap();
        assert_eq!(keys.address(), EXPECTED_ADDRESS);
    }

    #[test]
    fn test_abandon_mnemonic_sign_roundtrip() {
        use frost_core::keys::{KeyPackage, PublicKeyPackage};
        use frost_core::round1::SigningNonces;
        use crate::J;
        use frost_rerandomized::{Randomizer, RandomizedParams};

        let seed = abandon_seed();
        let import = run_key_import_native(3, 2, &seed, 0);

        let signer_indices = [0usize, 1];
        let signer_ids: Vec<u16> =
            signer_indices.iter().map(|i| (*i + 1) as u16).collect();

        let mut nonce_list = Vec::new();
        let mut commitments_entries = Vec::new();

        for &idx in &signer_indices {
            let kp = KeyPackage::<J>::deserialize(&import.results[idx].0).unwrap();
            let mut rng = rand::thread_rng();
            let (nonces, commitments) =
                frost_core::round1::commit(kp.signing_share(), &mut rng);
            nonce_list.push(nonces.serialize().unwrap());
            commitments_entries.push((
                signer_ids[commitments_entries.len()],
                commitments.serialize().unwrap(),
            ));
        }

        let commitments_map = encode_id_map(&commitments_entries);
        let pkp = PublicKeyPackage::<J>::deserialize(&import.results[0].1).unwrap();

        let message = b"abandon mnemonic cross-verify test";

        let commitments_decoded =
            crate::sign::decode_commitments_map(&commitments_map).unwrap();
        let signing_package =
            frost_core::SigningPackage::<J>::new(commitments_decoded, message.as_ref());

        let randomized_params = RandomizedParams::<J>::new(
            pkp.verifying_key(),
            &signing_package,
            rand::thread_rng(),
        )
        .unwrap();

        let randomizer_bytes = randomized_params.randomizer().serialize();
        let sp_bytes = signing_package.serialize().unwrap();

        let mut share_entries = Vec::new();

        for (i, &idx) in signer_indices.iter().enumerate() {
            let sp = frost_core::SigningPackage::<J>::deserialize(&sp_bytes).unwrap();
            let nonces = SigningNonces::<J>::deserialize(&nonce_list[i]).unwrap();
            let kp = KeyPackage::<J>::deserialize(&import.results[idx].0).unwrap();
            let randomizer = Randomizer::<J>::deserialize(&randomizer_bytes).unwrap();
            let share =
                frost_rerandomized::sign(&sp, &nonces, &kp, randomizer).unwrap();
            share_entries.push((signer_ids[i], share.serialize()));
        }

        let shares_map = encode_id_map(&share_entries);
        let shares_decoded = crate::sign::decode_shares_map(&shares_map).unwrap();
        let sp = frost_core::SigningPackage::<J>::deserialize(&sp_bytes).unwrap();
        let randomizer = Randomizer::<J>::deserialize(&randomizer_bytes).unwrap();
        let randomized_params =
            RandomizedParams::<J>::from_randomizer(pkp.verifying_key(), randomizer);

        let signature = frost_rerandomized::aggregate(
            &sp,
            &shares_decoded,
            &pkp,
            &randomized_params,
        )
        .unwrap();

        let sig_bytes = signature.serialize().unwrap();
        assert!(!sig_bytes.is_empty());
    }

    #[test]
    fn test_identifier_encode_decode() {
        for id in 1..=10u16 {
            let ident = Identifier::try_from(id).unwrap();
            let bytes = ident.serialize();
            let decoded = Identifier::deserialize(&bytes).unwrap();
            let back = identifier_to_u16(&decoded).unwrap();
            assert_eq!(id, back);
        }
    }

    #[test]
    fn test_tree_witness_roundtrip() {
        let mut tree = WasmSaplingTree::from_hex_state("000000").unwrap();

        for i in 1u8..=5 {
            let mut cmu = [0u8; 32];
            cmu[0] = i;
            tree.append(&cmu).unwrap();
        }

        let witness = tree.witness().unwrap();
        let root1 = witness.root().unwrap();

        let serialized = witness.serialize().unwrap();
        let witness2 = WasmSaplingWitness::from_bytes(&serialized).unwrap();
        let root2 = witness2.root().unwrap();
        assert_eq!(root1, root2);
    }

    #[wasm_bindgen_test]
    fn test_abandon_mnemonic_address_wasm() {
        test_abandon_mnemonic_address();
    }

    #[wasm_bindgen_test]
    fn test_abandon_mnemonic_sign_roundtrip_wasm() {
        test_abandon_mnemonic_sign_roundtrip();
    }

    #[wasm_bindgen_test]
    fn test_identifier_encode_decode_wasm() {
        test_identifier_encode_decode();
    }

    #[wasm_bindgen_test]
    fn test_tree_witness_roundtrip_wasm() {
        test_tree_witness_roundtrip();
    }

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
}
