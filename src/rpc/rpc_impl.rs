use crate::extensions::{
    ckb_balance, rce_validator, udt_balance, CKB_EXT_PREFIX, RCE_EXT_PREFIX, UDT_EXT_PREFIX,
};
use crate::types::RCECellPair;
use crate::utils::{parse_address, to_fixed_array};
use crate::{error::MercuryError, types::DeployedScriptConfig};
use crate::{rpc::MercuryRpc, stores::add_prefix};

use anyhow::Result;
use ckb_indexer::indexer::{self, DetailedLiveCell};
use ckb_indexer::store::{IteratorDirection, Store};
use ckb_jsonrpc_types::{Transaction, TransactionView};
use ckb_types::core::BlockNumber;
use ckb_types::{packed, prelude::*, H256};
use jsonrpc_core::{Error, Result as RpcResult};

use std::collections::HashMap;

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

    fn rce_tx_completion(&self, transaction: Transaction) -> RpcResult<TransactionView> {
        let _rce_pair = self
            .extract_rce_cells(&transaction)
            .map_err(|e| Error::invalid_params(e.to_string()))?;

        Ok(Default::default())
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
        let mut input_list = Vec::new();
        let mut output_list = Vec::new();

        for input in transaction.inputs.iter() {
            if let Some(cell) = self
                .get_detailed_live_cell(input.previous_output.clone().into())
                .map_err(|e| Error::invalid_params(e.to_string()))?
            {
                if self.is_rce_cell(&cell.cell_output) {
                    input_list.push(cell);
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
                output_list.push(output);
            }
        }

        if input_list.len() != output_list.len() {
            return Err(
                MercuryError::RCECellCountMismatch(input_list.len(), output_list.len()).into(),
            );
        }

        let ret = input_list
            .into_iter()
            .zip(output_list.into_iter())
            .map(|(input, output)| RCECellPair { input, output })
            .collect::<Vec<_>>();

        Ok(ret)
    }
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
