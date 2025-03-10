mod query;
mod transfer;

use crate::extensions::{rce_validator, RCE_EXT_PREFIX};
use crate::rpc::types::{
    CreateWalletPayload, GetBalanceResponse, TransactionCompletionResponse, TransferPayload,
};
use crate::rpc::MercuryRpc;
use crate::utils::parse_address;
use crate::{stores::add_prefix, types::DeployedScriptConfig};

use ckb_indexer::{indexer::DetailedLiveCell, store::Store};
use ckb_sdk::{AddressPayload, NetworkType};
use ckb_types::{packed, prelude::*, H256, U256};
use dashmap::DashMap;
use jsonrpc_core::{Error, Result as RpcResult};
use log::debug;
use parking_lot::RwLock;

use std::collections::{HashMap, HashSet};
use std::{iter::Iterator, thread::ThreadId};

pub const BYTE_SHANNONS: u64 = 100_000_000;
pub const STANDARD_SUDT_CAPACITY: u64 = 142 * BYTE_SHANNONS;
pub const CHEQUE_CELL_CAPACITY: u64 = 162 * BYTE_SHANNONS;
const MIN_CKB_CAPACITY: u64 = 61 * BYTE_SHANNONS;

lazy_static::lazy_static! {
    pub static ref TX_POOL_CACHE: RwLock<HashSet<packed::OutPoint>> = RwLock::new(HashSet::new());
    static ref ACP_USED_CACHE: DashMap<ThreadId, Vec<packed::OutPoint>> = DashMap::new();
}

macro_rules! rpc_try {
    ($input: expr) => {
        $input.map_err(|e| Error::invalid_params(e.to_string()))?
    };
}

pub struct MercuryRpcImpl<S> {
    store: S,
    net_ty: NetworkType,
    _cheque_since: U256,
    config: HashMap<String, DeployedScriptConfig>,
}

impl<S> MercuryRpc for MercuryRpcImpl<S>
where
    S: Store + Send + Sync + 'static,
{
    fn get_balance(&self, sudt_hash: Option<H256>, addr: String) -> RpcResult<GetBalanceResponse> {
        debug!("get udt {:?} balance address {:?}", sudt_hash, addr);
        let address = rpc_try!(parse_address(&addr));
        let ret = rpc_try!(self.inner_get_balance(sudt_hash, &address));
        debug!("sudt balance {:?}", ret);
        Ok(ret)
    }

    fn is_in_rce_list(&self, rce_hash: H256, addr: H256) -> RpcResult<bool> {
        let key = rce_validator::Key::Address(&rce_hash.pack(), &addr.pack()).into_vec();

        self.store
            .get(&add_prefix(*RCE_EXT_PREFIX, key))
            .map_or_else(|_| Err(Error::internal_error()), |res| Ok(res.is_some()))
    }

    fn build_transfer_transaction(
        &self,
        payload: TransferPayload,
    ) -> RpcResult<TransactionCompletionResponse> {
        debug!("transfer completion payload {:?}", payload);
        rpc_try!(payload.check());
        self.inner_transfer_complete(
            payload.udt_hash.clone(),
            payload.from.to_inner(),
            payload.to_inner_items(),
            payload.change.clone(),
            payload.fee,
        )
        .map_err(|e| Error::invalid_params(e.to_string()))
    }

    fn build_wallet_creation_transaction(
        &self,
        payload: CreateWalletPayload,
    ) -> RpcResult<TransactionCompletionResponse> {
        debug!("create wallet payload {:?}", payload);
        self.inner_create_wallet(payload.ident, payload.info, payload.fee)
            .map_err(|e| Error::invalid_params(e.to_string()))
    }
}

impl<S: Store> MercuryRpcImpl<S> {
    pub fn new(
        store: S,
        net_ty: NetworkType,
        _cheque_since: U256,
        config: HashMap<String, DeployedScriptConfig>,
    ) -> Self {
        MercuryRpcImpl {
            store,
            net_ty,
            _cheque_since,
            config,
        }
    }
}

fn address_to_script(payload: &AddressPayload) -> packed::Script {
    payload.into()
}

fn udt_iter(
    input: &[(DetailedLiveCell, packed::OutPoint)],
    hash: packed::Byte32,
) -> impl Iterator<Item = &(DetailedLiveCell, packed::OutPoint)> {
    input.iter().filter(move |(cell, _)| {
        if let Some(script) = cell.cell_output.type_().to_opt() {
            script.calc_script_hash() == hash
        } else {
            false
        }
    })
}

fn ckb_iter(
    cells: &[(DetailedLiveCell, packed::OutPoint)],
) -> impl Iterator<Item = &(DetailedLiveCell, packed::OutPoint)> {
    cells
        .iter()
        .filter(|(cell, _)| cell.cell_output.type_().is_none())
}
