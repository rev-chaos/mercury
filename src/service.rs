use crate::extensions::{build_extensions, CURRENT_EPOCH, MATURE_THRESHOLD};
use crate::rpc::{MercuryRpc, MercuryRpcImpl, TX_POOL_CACHE};
use crate::{stores::BatchStore, types::ExtensionsConfig};

use ckb_indexer::indexer::Indexer;
use ckb_indexer::service::{
    gen_client, get_block_by_number, get_raw_tx_pool, get_transaction, IndexerRpc, IndexerRpcImpl,
};
use ckb_indexer::store::{RocksdbStore, Store};
use ckb_jsonrpc_types::RawTxPool;
use ckb_sdk::NetworkType;
use ckb_types::core::{BlockNumber, BlockView, RationalU256};
use ckb_types::{packed, H256, U256};
use jsonrpc_core::IoHandler;
use jsonrpc_http_server::{Server, ServerBuilder};
use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
use jsonrpc_server_utils::hosts::DomainsValidation;
use log::{error, info, warn};
use tokio::time::{sleep, Duration};

use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const KEEP_NUM: u64 = 100;
const PRUNE_INTERVAL: u64 = 1000;
const GENESIS_NUMBER: u64 = 0;

// Adapted from https://github.com/nervosnetwork/ckb-indexer/blob/290ae55a2d2acfc3d466a69675a1a58fcade7f5d/src/service.rs#L25
// with extensions for more indexing features.
pub struct Service {
    store: RocksdbStore,
    poll_interval: Duration,
    listen_address: String,
    rpc_thread_num: usize,
    network_type: NetworkType,
    extensions_config: ExtensionsConfig,
    snapshot_interval: u64,
    snapshot_path: PathBuf,
    cellbase_maturity: RationalU256,
    cheque_since: U256,
}

impl Service {
    pub fn new(
        store_path: &str,
        listen_address: &str,
        poll_interval: Duration,
        rpc_thread_num: usize,
        network_ty: &str,
        extensions_config: ExtensionsConfig,
        snapshot_interval: u64,
        snapshot_path: &str,
        cellbase_maturity: u64,
        cheque_since: u64,
    ) -> Self {
        let store = RocksdbStore::new(store_path);
        let network_type = NetworkType::from_raw_str(network_ty).expect("invalid network type");
        let listen_address = listen_address.to_string();
        let snapshot_path = Path::new(snapshot_path).to_path_buf();
        let cellbase_maturity = RationalU256::from_u256(U256::from(cellbase_maturity));
        let cheque_since: U256 = cheque_since.into();

        info!("Mercury running in CKB {:?}", network_type);

        Service {
            store,
            poll_interval,
            listen_address,
            rpc_thread_num,
            network_type,
            extensions_config,
            snapshot_interval,
            snapshot_path,
            cellbase_maturity,
            cheque_since,
        }
    }

    pub fn start(&self) -> Server {
        let mut io_handler = IoHandler::new();
        let mercury_rpc_impl = MercuryRpcImpl::new(
            self.store.clone(),
            self.network_type,
            self.cheque_since.clone(),
            self.extensions_config.to_rpc_config(),
        );
        let indexer_rpc_impl = IndexerRpcImpl {
            store: self.store.clone(),
        };

        io_handler.extend_with(indexer_rpc_impl.to_delegate());
        io_handler.extend_with(mercury_rpc_impl.to_delegate());

        ServerBuilder::new(io_handler)
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Null,
                AccessControlAllowOrigin::Any,
            ]))
            .threads(self.rpc_thread_num)
            .health_api(("/ping", "ping"))
            .start_http(
                &self
                    .listen_address
                    .to_socket_addrs()
                    .expect("config listen_address parsed")
                    .next()
                    .expect("listen_address parsed"),
            )
            .expect("Start Jsonrpc HTTP service")
    }

    #[allow(clippy::cmp_owned)]
    pub async fn poll(&self, rpc_client: gen_client::Client) {
        // 0.37.0 and above supports hex format
        let use_hex_format = loop {
            match rpc_client.local_node_info().await {
                Ok(local_node_info) => {
                    break local_node_info.version > "0.36".to_owned();
                }

                Err(err) => {
                    // < 0.32.0 compatibility
                    if format!("#{}", err).contains("missing field") {
                        break false;
                    }

                    error!("cannot get local_node_info from ckb node: {}", err);

                    std::thread::sleep(self.poll_interval);
                }
            }
        };

        let use_hex = use_hex_format;
        let client_clone = rpc_client.clone();

        tokio::spawn(async move {
            update_tx_pool_cache(client_clone, use_hex).await;
        });

        self.run(rpc_client, use_hex_format).await;
    }

    async fn run(&self, rpc_client: gen_client::Client, use_hex_format: bool) {
        let mut tip = 0;

        loop {
            let batch_store =
                BatchStore::create(self.store.clone()).expect("batch store creation should be OK");
            let indexer = Arc::new(Indexer::new(batch_store.clone(), KEEP_NUM, u64::MAX));
            let extensions = build_extensions(
                self.network_type,
                &self.extensions_config,
                Arc::clone(&indexer),
                batch_store.clone(),
            )
            .expect("extension building failure");

            let append_block_func = |block: BlockView| {
                indexer.append(&block).expect("append block should be OK");
                extensions.iter().for_each(|extension| {
                    extension
                        .append(&block)
                        .unwrap_or_else(|e| panic!("append block error {:?}", e))
                });
            };

            // TODO: load tip first so extensions do not need to store their
            // own tip?
            let rollback_func = |tip_number: BlockNumber, tip_hash: packed::Byte32| {
                indexer.rollback().expect("rollback block should be OK");
                extensions.iter().for_each(|extension| {
                    extension
                        .rollback(tip_number, &tip_hash)
                        .unwrap_or_else(|e| panic!("rollback error {:?}", e))
                });
            };

            let mut prune = false;
            if let Some((tip_number, tip_hash)) = indexer.tip().expect("get tip should be OK") {
                tip = tip_number;

                match get_block_by_number(&rpc_client, tip_number + 1, use_hex_format).await {
                    Ok(Some(block)) => {
                        self.chenge_current_epoch(block.epoch().to_rational());

                        if block.parent_hash() == tip_hash {
                            info!("append {}, {}", block.number(), block.hash());
                            append_block_func(block.clone());
                            prune = (block.number() % PRUNE_INTERVAL) == 0;
                        } else {
                            info!("rollback {}, {}", tip_number, tip_hash);
                            rollback_func(tip_number, tip_hash);
                        }
                    }

                    Ok(None) => {
                        sleep(self.poll_interval).await;
                    }

                    Err(err) => {
                        error!("cannot get block from ckb node, error: {}", err);

                        sleep(self.poll_interval).await;
                    }
                }
            } else {
                match get_block_by_number(&rpc_client, GENESIS_NUMBER, use_hex_format).await {
                    Ok(Some(block)) => {
                        self.chenge_current_epoch(block.epoch().to_rational());
                        append_block_func(block);
                    }

                    Ok(None) => {
                        error!("ckb node returns an empty genesis block");

                        std::thread::sleep(self.poll_interval);
                    }

                    Err(err) => {
                        error!("cannot get genesis block from ckb node, error: {}", err);

                        std::thread::sleep(self.poll_interval);
                    }
                }
            }

            batch_store.commit().expect("commit should be OK");

            if prune {
                let store = BatchStore::create(self.store.clone())
                    .expect("batch store creation should be OK");
                let indexer = Arc::new(Indexer::new(store.clone(), KEEP_NUM, PRUNE_INTERVAL));
                let extensions = build_extensions(
                    self.network_type,
                    &self.extensions_config,
                    Arc::clone(&indexer),
                    store.clone(),
                )
                .expect("extension building failure");

                if let Some((tip_number, tip_hash)) = indexer.tip().expect("get tip should be OK") {
                    indexer.prune().expect("indexer prune should be OK");

                    for extension in extensions.iter() {
                        extension
                            .prune(tip_number, &tip_hash, KEEP_NUM)
                            .expect("extension prune should be OK");
                    }
                }

                store.commit().expect("commit should be OK");
            }

            self.snapshot(tip);
        }
    }

    fn snapshot(&self, height: u64) {
        if height % self.snapshot_interval != 0 {
            return;
        }

        let mut path = self.snapshot_path.clone();
        path.push(height.to_string());
        let store = self.store.clone();

        tokio::spawn(async move {
            if let Err(e) = store.checkpoint(path) {
                error!("build {} checkpoint failed: {:?}", height, e);
            }
        });
    }

    fn chenge_current_epoch(&self, current_epoch: RationalU256) {
        self.change_maturity_threshold(current_epoch.clone());

        let mut epoch = CURRENT_EPOCH.write();
        *epoch = current_epoch;
    }

    fn change_maturity_threshold(&self, current_epoch: RationalU256) {
        if current_epoch < self.cellbase_maturity {
            return;
        }

        let new = current_epoch - self.cellbase_maturity.clone();
        let mut threshold = MATURE_THRESHOLD.write();
        *threshold = new;
    }
}

async fn update_tx_pool_cache(client: gen_client::Client, use_hex_format: bool) {
    loop {
        match get_raw_tx_pool(&client, Some(use_hex_format)).await {
            Ok(raw_pool) => handle_raw_tx_pool(&client, raw_pool).await,
            Err(e) => error!("get raw tx pool error {:?}", e),
        }

        sleep(Duration::from_millis(200)).await;
    }
}

// Todo: can do perf here.
async fn handle_raw_tx_pool(client: &gen_client::Client, raw_pool: RawTxPool) {
    let mut input_set: HashSet<packed::OutPoint> = HashSet::new();

    for hash in tx_hash_iter(raw_pool) {
        if let Ok(Some(tx)) = get_transaction(client, hash).await {
            for input in tx.transaction.inner.inputs.into_iter() {
                input_set.insert(input.previous_output.into());
            }
        } else {
            warn!("Get tx pool transaction failed.");
        }
    }

    let mut pool_cache = TX_POOL_CACHE.write();
    *pool_cache = input_set;
}

#[allow(clippy::needless_collect)]
fn tx_hash_iter(raw_pool: RawTxPool) -> impl Iterator<Item = H256> {
    match raw_pool {
        RawTxPool::Ids(ids) => ids.pending.into_iter().chain(ids.proposed.into_iter()),
        RawTxPool::Verbose(map) => {
            let pending = map.pending.into_iter().map(|(k, _v)| k).collect::<Vec<_>>();
            pending.into_iter().chain(
                map.proposed
                    .into_iter()
                    .map(|(k, _v)| k)
                    .collect::<Vec<_>>(),
            )
        }
    }
}
