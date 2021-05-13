use crate::extensions::rce_validator::{self, generated::xudt_rce};
use crate::extensions::{ckb_balance, udt_balance, CKB_EXT_PREFIX, RCE_EXT_PREFIX, UDT_EXT_PREFIX};
use crate::types::{RCECellPair, SMTUpdateItem, SMTValue};
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

type SMT = smt::SparseMerkleTree<Blake2bHasher, SMTValue, DefaultStore<SMTValue>>;

pub struct MercuryRpcImpl<S> {
    store: S,
    config: HashMap<String, DeployedScriptConfig>,
}

impl<S> MercuryRpc for MercuryRpcImpl<S>
where
    S: Store + Send + Sync + 'static,
{
    fn get_ckb_balance(&self, addr: String) -> RpcResult<Option<u64>> {
        let address = parse_address(&addr).map_err(|e| Error::invalid_params(e.to_string()))?;
        let key: Vec<u8> = ckb_balance::Key::CkbAddress(&address.to_string()).into();

        self.store
            .get(&add_prefix(*CKB_EXT_PREFIX, key))
            .map_err(|_| Error::internal_error())?
            .map_or_else(
                || Ok(None),
                |bytes| Ok(Some(u64::from_be_bytes(to_fixed_array(&bytes)))),
            )
    }

    fn get_sudt_balance(&self, sudt_hash: H256, addr: String) -> RpcResult<Option<u128>> {
        let address = parse_address(&addr).map_err(|e| Error::invalid_params(e.to_string()))?;
        let mut encoded = sudt_hash.as_bytes().to_vec();
        encoded.extend_from_slice(&address.to_string().as_bytes());
        let key: Vec<u8> = udt_balance::Key::Address(&encoded).into();

        self.store
            .get(&add_prefix(*UDT_EXT_PREFIX, key))
            .map_err(|e| Error::invalid_params(e.to_string()))?
            .map_or_else(
                || Ok(None),
                |bytes| Ok(Some(u128::from_be_bytes(to_fixed_array(&bytes)))),
            )
    }

    fn get_xudt_balance(&self, xudt_hash: H256, addr: String) -> RpcResult<Option<u128>> {
        let address = parse_address(&addr).map_err(|e| Error::invalid_params(e.to_string()))?;
        let mut encoded = xudt_hash.as_bytes().to_vec();
        encoded.extend_from_slice(&address.to_string().as_bytes());
        let key: Vec<u8> = udt_balance::Key::Address(&encoded).into();

        self.store
            .get(&add_prefix(*UDT_EXT_PREFIX, key))
            .map_err(|e| Error::invalid_params(e.to_string()))?
            .map_or_else(
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

    fn rce_update_completion(
        &self,
        transaction: Transaction,
        update_item: Vec<SMTUpdateItem>,
    ) -> RpcResult<TransactionView> {
        let rce_pair = self
            .extract_rce_cells(&transaction)
            .map_err(|e| Error::invalid_params(e.to_string()))?;

        let rule = get_rc_rule(rce_pair.input.cell_data.as_slice());
        let root: [u8; 32] = rule.smt_root().unpack();
        let mut smt = SMT::new(root.into(), DefaultStore::default());

        self.update_smt(&mut smt, &update_item)
            .map_err(|e| Error::invalid_params(e.to_string()))?;

        let new_root: [u8; 32] = smt.root().to_owned().into();
        let output_data = build_rce_data(new_root, rule.flag());
        let witness_args = build_witness_args(&smt, update_item)
            .map_err(|e| Error::invalid_params(e.to_string()))?;

        Ok(build_rce_transaction(
            transaction.into(),
            rce_pair.index,
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
    fn extract_rce_cells(&self, transaction: &Transaction) -> Result<RCECellPair> {
        let mut pair = RCECellPair::default();

        for (idx, input) in transaction.inputs.iter().enumerate() {
            if let Some(cell) = self
                .get_detailed_live_cell(input.previous_output.clone().into())
                .map_err(|e| Error::invalid_params(e.to_string()))?
            {
                if self.is_rce_cell(&cell.cell_output) {
                    pair.set_index(idx);
                    pair.set_input(cell);
                }
            } else {
                return Err(
                    MercuryError::CannotFindCellByOutPoint(input.previous_output.clone()).into(),
                );
            }
        }

        for output in transaction.outputs.iter() {
            let output: packed::CellOutput = output.clone().into();
            if self.is_rce_cell(&output) {
                pair.set_output(output);
            }
        }

        Ok(pair)
    }

    fn update_smt(&self, smt: &mut SMT, update_items: &[SMTUpdateItem]) -> Result<()> {
        for item in update_items.iter() {
            smt.update(item.key.0.into(), item.val.into())
                .map_err(|e| MercuryError::SMTError(e.to_string()))?;
        }

        Ok(())
    }
}

fn get_rc_rule(data: &[u8]) -> xudt_rce::RCRule {
    let rc_data = xudt_rce::RCData::from_slice(data)
        .expect("invalid data format")
        .to_enum();

    match rc_data {
        xudt_rce::RCDataUnion::RCRule(rule) => rule,
        xudt_rce::RCDataUnion::RCCellVec(_cells) => unreachable!(),
    }
}

fn build_rce_transaction(
    origin: packed::Transaction,
    index: usize,
    cell_data: Bytes,
    witness_args: Bytes,
) -> TransactionView {
    let mut witness = origin.witnesses().unpack();
    let mut output_data = origin.clone().into_view().outputs_data().unpack();
    swap_item(&mut witness, index, witness_args);
    swap_item(&mut output_data, index, cell_data);

    origin
        .as_advanced_builder()
        .witnesses(witness.pack())
        .outputs_data(output_data.pack())
        .build()
        .into()
}

fn swap_item<T>(list: &mut [T], index: usize, new_item: T) {
    *list.get_mut(index).unwrap() = new_item;
}

fn build_rce_data(root: [u8; 32], flag: packed::Byte) -> Bytes {
    xudt_rce::RCDataBuilder(xudt_rce::RCDataUnion::RCRule(
        xudt_rce::RCRuleBuilder::default()
            .flag(flag)
            .smt_root(root.pack())
            .build(),
    ))
    .build()
    .as_bytes()
}

fn build_witness_args(smt: &SMT, update_item: Vec<SMTUpdateItem>) -> Result<Bytes> {
    let keys = update_item
        .iter()
        .map(|item| item.key.0.into())
        .collect::<Vec<smt::H256>>();
    let smt_proof = smt
        .merkle_proof(keys)
        .map_err(|e| MercuryError::SMTError(e.to_string()))?
        .take();

    let leaves_path = packed::BytesVecBuilder::default()
        .set(
            smt_proof
                .0
                .iter()
                .map(|bytes| bytes.pack())
                .collect::<Vec<_>>(),
        )
        .build();

    let proof = xudt_rce::ProofVecBuilder(
        smt_proof
            .1
            .iter()
            .map(|proof| {
                let hash: [u8; 32] = proof.0.clone().into();
                xudt_rce::ProofBuilder::default()
                    .path(hash.pack())
                    .height(proof.1.into())
                    .build()
            })
            .collect::<Vec<_>>(),
    )
    .build();

    let merkle_proof = xudt_rce::MerkleProofBuilder::default()
        .leaves_path(leaves_path)
        .proof(proof)
        .build()
        .as_slice()
        .iter()
        .map(|byte| packed::Byte::from(*byte))
        .collect::<Vec<_>>();

    let update_inner = update_item
        .into_iter()
        .map(|item| {
            xudt_rce::SmtUpdateItemBuilder::default()
                .key(item.key.pack())
                .values(item.val.into())
                .build()
        })
        .collect::<Vec<_>>();
    let update = xudt_rce::SmtUpdateVecBuilder(update_inner).build();

    Ok(xudt_rce::SmtUpdateBuilder::default()
        .proof(xudt_rce::SmtProofBuilder(merkle_proof).build())
        .update(update)
        .build()
        .as_bytes())
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
