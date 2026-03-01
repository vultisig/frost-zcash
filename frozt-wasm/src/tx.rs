use std::io;
use std::rc::Rc;

use group::ff::{Field, PrimeField};
use sapling_crypto::{
    circuit::{OutputParameters, SpendParameters},
    keys::{FullViewingKey, OutgoingViewingKey},
    note_encryption::Zip212Enforcement,
    value::{NoteValue, ValueCommitTrapdoor},
    Diversifier, Note, ProofGenerationKey, Rseed,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use froztlib::errors::lib_error;
use froztlib::tx::{self, TxBuildState, SpendParts, OutputParts};

fn to_js(e: lib_error) -> JsError {
    JsError::new(&format!("{}", e))
}

#[wasm_bindgen]
pub struct WasmSaplingProver {
    spend_params: Rc<SpendParameters>,
    output_params: Rc<OutputParameters>,
}

#[wasm_bindgen]
impl WasmSaplingProver {
    #[wasm_bindgen(constructor)]
    pub fn new(
        spend_params_bytes: &[u8],
        output_params_bytes: &[u8],
    ) -> Result<WasmSaplingProver, JsError> {
        let spend_params =
            SpendParameters::read(io::Cursor::new(spend_params_bytes), true)
                .map_err(|e| JsError::new(&format!("read spend params: {}", e)))?;
        let output_params =
            OutputParameters::read(io::Cursor::new(output_params_bytes), true)
                .map_err(|e| JsError::new(&format!("read output params: {}", e)))?;
        Ok(WasmSaplingProver {
            spend_params: Rc::new(spend_params),
            output_params: Rc::new(output_params),
        })
    }

    #[wasm_bindgen(js_name = "createBuilder")]
    pub fn create_builder(
        &self,
        pkp_bytes: &[u8],
        extras_bytes: &[u8],
        target_height: u32,
    ) -> Result<WasmTxBuilder, JsError> {
        if extras_bytes.len() != 96 {
            return Err(JsError::new("extras must be 96 bytes"));
        }

        let dfvk_raw = froztlib::sapling::build_dfvk_raw(pkp_bytes, extras_bytes)
            .map_err(to_js)?;
        let dfvk = sapling_crypto::zip32::DiversifiableFullViewingKey::from_bytes(&dfvk_raw)
            .ok_or_else(|| JsError::new("invalid dfvk derived from pkp+extras"))?;
        let fvk = dfvk.fvk().clone();

        let mut nsk_arr: [u8; 32] = extras_bytes[..32].try_into().unwrap();
        let nsk: Option<jubjub::Fr> = jubjub::Fr::from_repr(nsk_arr).into();
        nsk_arr.zeroize();
        let nsk = nsk.ok_or_else(|| JsError::new("invalid nsk scalar"))?;
        let pgk = ProofGenerationKey { ak: fvk.vk.ak.clone(), nsk };
        let ovk = fvk.ovk;
        let zip212 = froztlib::sapling::zip212_for_height(target_height as u64);

        Ok(WasmTxBuilder {
            fvk,
            pgk,
            ovk,
            target_height,
            zip212,
            spend_params: Rc::clone(&self.spend_params),
            output_params: Rc::clone(&self.output_params),
            spends: Vec::new(),
            outputs: Vec::new(),
            alphas: Vec::new(),
            total_input: 0,
            total_output: 0,
            finished: None,
            sighash_bytes: None,
        })
    }

}

#[wasm_bindgen]
pub struct WasmTxBuilder {
    fvk: FullViewingKey,
    pgk: ProofGenerationKey,
    ovk: OutgoingViewingKey,
    target_height: u32,
    zip212: Zip212Enforcement,
    spend_params: Rc<SpendParameters>,
    output_params: Rc<OutputParameters>,
    spends: Vec<SpendParts>,
    outputs: Vec<OutputParts>,
    alphas: Vec<[u8; 32]>,
    total_input: u64,
    total_output: u64,
    finished: Option<TxBuildState>,
    sighash_bytes: Option<[u8; 32]>,
}

impl Drop for WasmTxBuilder {
    fn drop(&mut self) {
        froztlib::zeroize_scalar(&mut self.pgk.nsk);
        for alpha in &mut self.alphas {
            alpha.zeroize();
        }
    }
}

#[wasm_bindgen]
impl WasmTxBuilder {
    #[wasm_bindgen(js_name = "addSpend")]
    pub fn add_spend(&mut self, note_data: &[u8], witness_data: &[u8]) -> Result<Vec<u8>, JsError> {
        if note_data.len() != 51 {
            return Err(JsError::new("note_data must be 51 bytes"));
        }

        let diversifier = Diversifier(note_data[..11].try_into().unwrap());
        let value_bytes: [u8; 8] = note_data[11..19].try_into().unwrap();
        let value = NoteValue::from_raw(u64::from_le_bytes(value_bytes));
        let rseed_bytes: [u8; 32] = note_data[19..51].try_into().unwrap();

        let rseed = match self.zip212 {
            Zip212Enforcement::On => Rseed::AfterZip212(rseed_bytes),
            _ => {
                let rcm: Option<jubjub::Fr> = jubjub::Fr::from_repr(rseed_bytes).into();
                Rseed::BeforeZip212(rcm.ok_or_else(|| JsError::new("invalid rcm"))?)
            }
        };

        let pk_d = self.fvk.vk.to_payment_address(diversifier)
            .ok_or_else(|| JsError::new("invalid payment address from diversifier"))?;
        let note = Note::from_parts(pk_d, value, rseed);

        let witness = froztlib::tree::deserialize_witness(witness_data).map_err(to_js)?;
        let merkle_path = witness.path()
            .ok_or_else(|| JsError::new("witness has no path"))?;

        let mut alpha = jubjub::Fr::random(&mut rand::thread_rng());
        let spend = tx::make_spend(&self.pgk, &self.fvk, &note, &merkle_path, alpha, &self.spend_params)
            .map_err(to_js)?;

        let mut alpha_repr = alpha.to_repr();
        froztlib::zeroize_scalar(&mut alpha);
        let alpha_bytes: [u8; 32] = alpha_repr;
        alpha_repr.zeroize();

        self.total_input += value.inner();
        self.spends.push(spend);
        self.alphas.push(alpha_bytes);

        Ok(alpha_bytes.to_vec())
    }

    #[wasm_bindgen(js_name = "addOutput")]
    pub fn add_output(&mut self, address: &str, amount: f64) -> Result<(), JsError> {
        let amount = amount as u64;
        let addr = tx::parse_payment_address(address).map_err(to_js)?;
        let memo = [0u8; 512];

        let output = tx::make_output(
            Some(self.ovk),
            addr,
            NoteValue::from_raw(amount),
            memo,
            self.zip212,
            &self.output_params,
        ).map_err(to_js)?;

        self.total_output += amount;
        self.outputs.push(output);
        Ok(())
    }

    pub fn build(&mut self) -> Result<(), JsError> {
        if self.spends.is_empty() {
            return Err(JsError::new("no spends added"));
        }
        if self.total_output > self.total_input {
            return Err(JsError::new("outputs exceed inputs"));
        }
        let fee = self.total_input - self.total_output;
        if fee > 1_000_000 {
            return Err(JsError::new("fee exceeds maximum"));
        }

        let spends = std::mem::take(&mut self.spends);
        let outputs = std::mem::take(&mut self.outputs);

        let value_balance = fee as i64;
        let consensus_branch_id = tx::branch_id_for_height(self.target_height);
        let expiry_height = self.target_height + 100;

        let sighash = tx::compute_v5_sighash(
            &spends, &outputs,
            value_balance, consensus_branch_id, expiry_height,
        );

        let state = TxBuildState {
            spends,
            outputs,
            value_balance,
            consensus_branch_id,
            expiry_height,
            sighash,
        };

        self.finished = Some(state);
        self.sighash_bytes = Some(sighash);
        Ok(())
    }

    #[wasm_bindgen(getter)]
    pub fn sighash(&self) -> Vec<u8> {
        match &self.sighash_bytes {
            Some(sh) => sh.to_vec(),
            None => Vec::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn alpha(&self) -> Vec<u8> {
        if self.alphas.is_empty() {
            return Vec::new();
        }
        self.alphas[0].to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn alphas(&self) -> Vec<u8> {
        self.alphas.iter().flat_map(|a| a.iter().copied()).collect()
    }

    #[wasm_bindgen(getter, js_name = "numSpends")]
    pub fn num_spends(&self) -> usize {
        self.alphas.len()
    }

    pub fn complete(&mut self, spend_auth_sigs: &[u8]) -> Result<Vec<u8>, JsError> {
        let state = self.finished.take()
            .ok_or_else(|| JsError::new("build() must be called before complete()"))?;

        let n_spends = state.spends.len();
        if spend_auth_sigs.len() != 64 * n_spends {
            return Err(JsError::new(&format!(
                "expected {} bytes ({} * 64), got {}",
                64 * n_spends, n_spends, spend_auth_sigs.len()
            )));
        }

        let mut sigs = Vec::with_capacity(n_spends);
        for i in 0..n_spends {
            let sig_bytes: [u8; 64] = spend_auth_sigs[i*64..(i+1)*64].try_into().unwrap();
            sigs.push(redjubjub::Signature::<redjubjub::SpendAuth>::from(sig_bytes));
        }

        let spend_rcvs: Vec<&ValueCommitTrapdoor> = state.spends.iter().map(|s| &s.rcv).collect();
        let output_rcvs: Vec<&ValueCommitTrapdoor> = state.outputs.iter().map(|o| &o.rcv).collect();
        let bsk = tx::compute_bsk(&spend_rcvs, &output_rcvs);

        let mut rng = rand::thread_rng();
        let binding_sig = bsk.sign(&mut rng, &state.sighash);

        let raw_tx = tx::serialize_v5_tx(
            &state.spends, &state.outputs, state.value_balance,
            &sigs, &binding_sig,
            state.consensus_branch_id, state.expiry_height,
        ).map_err(to_js)?;

        Ok(raw_tx)
    }
}
