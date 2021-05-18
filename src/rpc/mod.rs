pub mod rpc_impl;

use crate::types::SMTUpdateItem;

use ckb_jsonrpc_types::{Transaction, TransactionView};
use ckb_types::H256;
use jsonrpc_core::Result as RpcResult;
use jsonrpc_derive::rpc;

pub use rpc_impl::MercuryRpcImpl;

#[rpc(server)]
pub trait MercuryRpc {
    #[rpc(name = "get_ckb_balance")]
    fn get_ckb_balance(&self, addr: String) -> RpcResult<Option<u64>>;

    #[rpc(name = "get_sudt_balance")]
    fn get_sudt_balance(&self, sudt_hash: H256, addr: String) -> RpcResult<Option<u128>>;

    #[rpc(name = "get_xudt_balance")]
    fn get_xudt_balance(&self, xudt_hash: H256, addr: String) -> RpcResult<Option<u128>>;

    #[rpc(name = "is_in_rce_list")]
    fn is_in_rce_list(&self, rce_hash: H256, addr: H256) -> RpcResult<bool>;

    #[rpc(name = "transfer_with_rce_completion")]
    fn transfer_with_rce_completion(&self, transaction: Transaction) -> RpcResult<TransactionView>;

    #[rpc(name = "rce_update_completion")]
    fn rce_update_completion(
        &self,
        transaction: Transaction,
        smt_update: Vec<SMTUpdateItem>,
    ) -> RpcResult<TransactionView>;
}
