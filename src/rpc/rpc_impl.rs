use crate::extensions::rce_validator::{self, generated::xudt_rce};
use crate::extensions::{ckb_balance, udt_balance, CKB_EXT_PREFIX, RCE_EXT_PREFIX, UDT_EXT_PREFIX};
use crate::types::{RCECellPair, SMTUpdateItem};
use crate::utils::{parse_address, to_fixed_array};
use crate::{error::MercuryError, types::DeployedScriptConfig};
use crate::{rpc::MercuryRpc, stores::add_prefix};

use anyhow::Result;
use ckb_indexer::indexer::{self, DetailedLiveCell};
use ckb_indexer::store::{IteratorDirection, Store};
use ckb_jsonrpc_types::{Transaction, TransactionView};
use ckb_types::{bytes::Bytes, core::BlockNumber};
use ckb_types::{packed, prelude::*, H256};
use jsonrpc_core::{Error, Result as RpcResult};
use smt::{blake2b::Blake2bHasher, default_store::DefaultStore};

use std::collections::HashMap;

type SMT = smt::SparseMerkleTree<Blake2bHasher, smt::H256, DefaultStore<smt::H256>>;

macro_rules! rpc_try {
    ($input: expr) => {
        $input.map_err(|e| Error::invalid_params(e.to_string()))?
    };
}

pub struct MercuryRpcImpl<S> {
    store: S,
    config: HashMap<String, DeployedScriptConfig>,
}

impl<S> MercuryRpc for MercuryRpcImpl<S>
where
    S: Store + Send + Sync + 'static,
{
    fn get_ckb_balance(&self, addr: String) -> RpcResult<Option<u64>> {
        let address = rpc_try!(parse_address(&addr));
        let key: Vec<u8> = ckb_balance::Key::CkbAddress(&address.to_string()).into();

        rpc_try!(self.store.get(&add_prefix(*CKB_EXT_PREFIX, key))).map_or_else(
            || Ok(None),
            |bytes| Ok(Some(u64::from_be_bytes(to_fixed_array(&bytes)))),
        )
    }

    fn get_sudt_balance(&self, sudt_hash: H256, addr: String) -> RpcResult<Option<u128>> {
        let address = rpc_try!(parse_address(&addr));
        let mut encoded = sudt_hash.as_bytes().to_vec();
        encoded.extend_from_slice(&address.to_string().as_bytes());
        let key: Vec<u8> = udt_balance::Key::Address(&encoded).into();

        rpc_try!(self.store.get(&add_prefix(*UDT_EXT_PREFIX, key))).map_or_else(
            || Ok(None),
            |bytes| Ok(Some(u128::from_be_bytes(to_fixed_array(&bytes)))),
        )
    }

    fn get_xudt_balance(&self, xudt_hash: H256, addr: String) -> RpcResult<Option<u128>> {
        let address = rpc_try!(parse_address(&addr));
        let mut encoded = xudt_hash.as_bytes().to_vec();
        encoded.extend_from_slice(&address.to_string().as_bytes());
        let key: Vec<u8> = udt_balance::Key::Address(&encoded).into();

        rpc_try!(self.store.get(&add_prefix(*UDT_EXT_PREFIX, key))).map_or_else(
            || Ok(None),
            |bytes| Ok(Some(u128::from_be_bytes(to_fixed_array(&bytes)))),
        )
    }

    fn is_in_rce_list(&self, rce_hash: H256, addr: H256) -> RpcResult<bool> {
        let key = rce_validator::Key::Address(&rce_hash.pack(), &addr.pack()).into_vec();

        self.store
            .get(&add_prefix(*RCE_EXT_PREFIX, key))
            .map_or_else(
                |err| Err(Error::invalid_params(err.to_string())),
                |res| Ok(res.is_some()),
            )
    }

    fn transfer_with_rce_completion(&self, transaction: Transaction) -> RpcResult<TransactionView> {
        let tx: packed::Transaction = transaction.into();
        let mut witnesses = tx.witnesses().unpack();
        let tx_view = tx.clone().into_view();

        for (idx, (input, output)) in tx_view
            .inputs()
            .into_iter()
            .zip(tx_view.outputs().into_iter())
            .enumerate()
        {
            let input_detail = rpc_try!(self
                .get_detailed_live_cell(input.previous_output())
                .map_err(|e| Error::invalid_params(e.to_string()))?
                .ok_or_else(|| MercuryError::CannotFindCellByOutPoint(
                    input.previous_output().into(),
                )));

            let input_hash: [u8; 32] = input_detail.cell_output.lock().calc_script_hash().unpack();
            let output_hash: [u8; 32] = output.lock().calc_script_hash().unpack();
            let keys: Vec<smt::H256> = vec![input_hash.clone().into(), output_hash.clone().into()];
            let leaves: Vec<(smt::H256, smt::H256)> = vec![
                (input_hash.into(), build_smt_value(true)),
                (output_hash.into(), build_smt_value(true)),
            ];

            let xudt_data =
                xudt_rce::XudtData::from_slice(input_detail.cell_data.as_slice()).unwrap();
            let rce_data =
                xudt_rce::RCRule::from_slice(xudt_data.data().get(0).unwrap().as_slice()).unwrap();
            let root: [u8; 32] = rce_data.smt_root().unpack();
            let smt = SMT::new(root.into(), DefaultStore::default());
            let proof: Vec<u8> = rpc_try!(rpc_try!(smt.merkle_proof(keys)).compile(leaves)).into();

            change_witness(&mut witnesses, idx, proof.into());
        }

        let w = witnesses
            .into_iter()
            .map(|bytes| bytes.pack())
            .collect::<Vec<packed::Bytes>>();

        Ok(tx.as_advanced_builder().set_witnesses(w).build().into())
    }

    // TODO: Support to update multiple rce script in one transaction
    fn rce_update_completion(
        &self,
        transaction: Transaction,
        update_items: Vec<SMTUpdateItem>,
    ) -> RpcResult<TransactionView> {
        let rce_pairs = rpc_try!(self.extract_rce_cells(&transaction));

        let rule = self.get_rc_rule(rce_pairs[0].input.cell_data.as_slice());
        let old_root: [u8; 32] = rule.smt_root().unpack();
        let mut smt = SMT::new(old_root.into(), DefaultStore::default());

        let proof = rpc_try!(self.build_proof(&smt, &update_items));
        rpc_try!(self.update_smt(&mut smt, &update_items));

        let new_root: [u8; 32] = smt.root().to_owned().into();
        let output_data = self.build_rce_data(new_root, rule.flags());
        let witness_args = rpc_try!(self.build_witness_args(proof, &update_items));

        Ok(self.build_rce_transaction(
            transaction.into(),
            rce_pairs[0].index,
            output_data,
            witness_args,
        ))
    }
}

impl<S: Store> MercuryRpcImpl<S> {
    pub fn new(store: S, config: HashMap<String, DeployedScriptConfig>) -> Self {
        MercuryRpcImpl { store, config }
    }

    // TODO: can do perf here
    fn is_rce_cell(&self, cell: &packed::CellOutput) -> bool {
        if let Some(rce_config) = self.config.get(rce_validator::RCE) {
            if let Some(type_script) = cell.type_().to_opt() {
                if type_script.code_hash() == rce_config.script.code_hash()
                    && rce_config.script.hash_type() == type_script.hash_type()
                {
                    return true;
                }
            }
        }

        false
    }

    fn get_detailed_live_cell(
        &self,
        out_point: packed::OutPoint,
    ) -> Result<Option<DetailedLiveCell>> {
        let key_vec = indexer::Key::OutPoint(&out_point).into_vec();
        let (block_number, tx_index, cell_output, cell_data) = match self.store.get(&key_vec)? {
            Some(stored_cell) => indexer::Value::parse_cell_value(&stored_cell),
            None => return Ok(None),
        };
        let mut header_start_key = vec![indexer::KeyPrefix::Header as u8];
        header_start_key.extend_from_slice(&block_number.to_be_bytes());

        let block_hash = match self
            .store
            .iter(&header_start_key, IteratorDirection::Forward)?
            .next()
        {
            Some((key, _)) => {
                if key.starts_with(&header_start_key) {
                    let start = std::mem::size_of::<BlockNumber>() + 1;
                    packed::Byte32::from_slice(&key[start..start + 32])
                        .expect("stored key header hash")
                } else {
                    return Ok(None);
                }
            }
            None => return Ok(None),
        };

        Ok(Some(indexer::DetailedLiveCell {
            block_number,
            block_hash,
            tx_index,
            cell_output,
            cell_data,
        }))
    }

    // TODO: can do perf here
    fn extract_rce_cells(&self, transaction: &Transaction) -> Result<Vec<RCECellPair>> {
        let mut ret = Vec::new();

        for (idx, (input, output)) in transaction
            .inputs
            .iter()
            .zip(transaction.outputs.iter())
            .enumerate()
        {
            if let Some(cell) = self
                .get_detailed_live_cell(input.previous_output.clone().into())
                .map_err(|e| Error::invalid_params(e.to_string()))?
            {
                if self.is_rce_cell(&cell.cell_output) {
                    let output: packed::CellOutput = output.clone().into();

                    if !self.is_rce_cell(&output) {
                        return Err(MercuryError::InvalidOutputCellWhenUpdateRCE.into());
                    }

                    ret.push(RCECellPair {
                        index: idx,
                        input: cell,
                        output,
                    });
                }
            } else {
                return Err(
                    MercuryError::CannotFindCellByOutPoint(input.previous_output.clone()).into(),
                );
            }
        }

        Ok(ret)
    }

    fn build_proof(&self, smt: &SMT, update_items: &[SMTUpdateItem]) -> Result<Vec<u8>> {
        let mut keys = Vec::new();
        let mut leaves = Vec::new();

        for item in update_items.iter() {
            let key: smt::H256 = item.key.0.into();
            let val = smt
                .get(&key)
                .map_err(|e| MercuryError::SMTError(e.to_string()))?;
            keys.push(key);
            leaves.push((key, val));
        }

        let proof = smt
            .merkle_proof(keys)
            .map_err(|e| MercuryError::SMTError(e.to_string()))?
            .compile(leaves)
            .map_err(|e| MercuryError::SMTError(e.to_string()))?;

        Ok(proof.into())
    }

    // TODO: deny reduplicate key in the update list now.
    fn update_smt(&self, smt: &mut SMT, update_items: &[SMTUpdateItem]) -> Result<()> {
        for item in update_items.iter() {
            smt.update(item.key.0.into(), build_smt_value(item.new_val == 1))
                .map_err(|e| MercuryError::SMTError(e.to_string()))?;
        }

        Ok(())
    }

    fn get_rc_rule(&self, data: &[u8]) -> xudt_rce::RCRule {
        let rc_data = xudt_rce::RCData::from_slice(data)
            .expect("invalid data format")
            .to_enum();

        match rc_data {
            xudt_rce::RCDataUnion::RCRule(rule) => rule,
            xudt_rce::RCDataUnion::RCCellVec(_cells) => unreachable!(),
        }
    }

    fn build_rce_transaction(
        &self,
        origin: packed::Transaction,
        index: usize,
        cell_data: Bytes,
        witness_args: Bytes,
    ) -> TransactionView {
        let mut witness = origin.witnesses().unpack();
        let mut output_data = origin.clone().into_view().outputs_data().unpack();
        change_witness(&mut witness, index, witness_args);
        change_witness(&mut output_data, index, cell_data);

        origin
            .as_advanced_builder()
            .witnesses(witness.pack())
            .outputs_data(output_data.pack())
            .build()
            .into()
    }

    fn build_rce_data(&self, root: [u8; 32], flag: packed::Byte) -> Bytes {
        xudt_rce::RCDataBuilder(xudt_rce::RCDataUnion::RCRule(
            xudt_rce::RCRuleBuilder::default()
                .flags(flag)
                .smt_root(root.pack())
                .build(),
        ))
        .build()
        .as_bytes()
    }

    fn build_witness_args(&self, proof: Vec<u8>, update_item: &[SMTUpdateItem]) -> Result<Bytes> {
        let update_inner = update_item
            .iter()
            .map(|item| {
                xudt_rce::SmtUpdateItemBuilder::default()
                    .key(item.key.pack())
                    .values(item.new_val.into())
                    .build()
            })
            .collect::<Vec<_>>();
        let update = xudt_rce::SmtUpdateVecBuilder(update_inner).build();
        let merkle_proof =
            xudt_rce::SmtProofBuilder(proof.into_iter().map(Into::into).collect()).build();

        Ok(xudt_rce::SmtUpdateBuilder::default()
            .proof(merkle_proof)
            .update(update)
            .build()
            .as_bytes())
    }
}

fn build_smt_value(is_in: bool) -> smt::H256 {
    let v = is_in.into();
    let ret: [u8; 32] = array_init::array_init(|i| if i == 0 { v } else { 0 });
    ret.into()
}

fn swap_item<T>(list: &mut [T], index: usize, new_item: T) {
    *list.get_mut(index).unwrap() = new_item;
}

fn change_witness(witnesses: &mut [Bytes], index: usize, witness_type_args: Bytes) {
    let witness_args = packed::WitnessArgs::from_slice(&witnesses[index]).unwrap();
    let new_witness = witness_args
        .as_builder()
        .input_type(Some(witness_type_args).pack())
        .build()
        .as_bytes();

    swap_item(witnesses, index, new_witness);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::tests::{build_extension, MemoryDB};
    use crate::extensions::ExtensionType;
    use crate::stores::BatchStore;

    use ckb_indexer::indexer::Indexer;
    use ckb_sdk::{Address, NetworkType};
    use ckb_types::core::{
        capacity_bytes, BlockBuilder, Capacity, HeaderBuilder, ScriptHashType, TransactionBuilder,
    };
    use ckb_types::packed::{CellInput, CellOutputBuilder, Script, ScriptBuilder};
    use ckb_types::{bytes::Bytes, H256};

    use std::sync::Arc;

    const SHANNON_PER_CKB: u64 = 100_000_000;

    #[test]
    fn test_rpc_get_ckb_balance() {
        let store = MemoryDB::new(0u32.to_string().as_str());
        let indexer = Arc::new(Indexer::new(store.clone(), 10, u64::MAX));
        let batch_store = BatchStore::create(store.clone()).unwrap();

        let ckb_ext = build_extension(
            &ExtensionType::CkbBalance,
            Default::default(),
            Arc::clone(&indexer),
            batch_store.clone(),
        );
        let rpc = MercuryRpcImpl::new(store, HashMap::new());

        // setup test data
        let lock_script1 = ScriptBuilder::default()
            .code_hash(H256(rand::random()).pack())
            .hash_type(ScriptHashType::Data.into())
            .args(Bytes::from(b"lock_script1".to_vec()).pack())
            .build();

        let lock_script2 = ScriptBuilder::default()
            .code_hash(H256(rand::random()).pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(b"lock_script2".to_vec()).pack())
            .build();

        let type_script1 = ScriptBuilder::default()
            .code_hash(H256(rand::random()).pack())
            .hash_type(ScriptHashType::Data.into())
            .args(Bytes::from(b"type_script1".to_vec()).pack())
            .build();

        let type_script2 = ScriptBuilder::default()
            .code_hash(H256(rand::random()).pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(b"type_script2".to_vec()).pack())
            .build();

        let cellbase0 = TransactionBuilder::default()
            .input(CellInput::new_cellbase_input(0))
            .witness(Script::default().into_witness())
            .output(
                CellOutputBuilder::default()
                    .capacity(capacity_bytes!(1000).pack())
                    .lock(lock_script1.clone())
                    .build(),
            )
            .output_data(Default::default())
            .build();

        let tx00 = TransactionBuilder::default()
            .output(
                CellOutputBuilder::default()
                    .capacity(capacity_bytes!(1000).pack())
                    .lock(lock_script1.clone())
                    .type_(Some(type_script1).pack())
                    .build(),
            )
            .output_data(Default::default())
            .build();

        let tx01 = TransactionBuilder::default()
            .output(
                CellOutputBuilder::default()
                    .capacity(capacity_bytes!(2000).pack())
                    .lock(lock_script2.clone())
                    .type_(Some(type_script2).pack())
                    .build(),
            )
            .output_data(Default::default())
            .build();

        let block0 = BlockBuilder::default()
            .transaction(cellbase0)
            .transaction(tx00)
            .transaction(tx01)
            .header(HeaderBuilder::default().number(0.pack()).build())
            .build();

        ckb_ext.append(&block0).unwrap();
        batch_store.commit().unwrap();

        let block_hash = block0.hash();
        let unpack_0: H256 = block_hash.unpack();
        let unpack_1: [u8; 32] = block_hash.unpack();
        assert_eq!(unpack_0.as_bytes(), unpack_1.as_ref());

        let addr00 = Address::new(NetworkType::Testnet, lock_script1.into());
        let addr01 = Address::new(NetworkType::Testnet, lock_script2.into());
        let balance00 = rpc.get_ckb_balance(addr00.to_string()).unwrap();
        let balance01 = rpc.get_ckb_balance(addr01.to_string()).unwrap();

        assert_eq!(balance00.unwrap(), 1000 * SHANNON_PER_CKB);
        assert_eq!(balance01.unwrap(), 2000 * SHANNON_PER_CKB);
    }
}
