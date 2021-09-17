use super::*;

use crate::rpc_impl::{CURRENT_BLOCK_NUMBER, CURRENT_EPOCH_NUMBER};
use crate::tests::RpcTestEngine;
use crate::types::{
    decode_record_id, encode_record_id, AddressOrLockHash, AssetInfo, Balance, From as From2,
    GetBalancePayload, GetBlockInfoPayload, Identity, IdentityFlag, Item, JsonItem, Mode, Record,
    RecordId, SinceConfig, SinceFlag, SinceType, Source, To, ToInfo, TransactionInfo,
};
use ckb_types::{H160, H256};
use common::{Address, DetailedCell, NetworkType};
use std::collections::HashSet;
use std::str::FromStr;

use ckb_jsonrpc_types::CellOutput;
use ckb_types::core::BlockNumber;
use ckb_types::packed::{Bytes, OutPoint, Script};
use ckb_types::prelude::Pack;
use common::utils::to_fixed_array;
use core::convert::From;
use std::sync::Arc;
use tokio::test;

const MAINNET_PG_HOST: &str = "8.210.250.164";
const TESTNET_PG_HOST: &str = "47.243.132.16";

async fn new_rpc(network: NetworkType) -> MercuryRpcImpl<CkbRpcClient> {
    let host = match network {
        NetworkType::Mainnet => MAINNET_PG_HOST,
        NetworkType::Testnet => TESTNET_PG_HOST,
        _ => unreachable!(),
    };
    let engine = RpcTestEngine::new_pg(network, host).await;
    engine.rpc(network)
}

fn new_identity(address: &str) -> Identity {
    let address = Address::from_str(address).unwrap();
    let script = address_to_script(address.payload());
    let pub_key_hash = H160::from_slice(&script.args().as_slice()[4..24]).unwrap();
    println!("pubkey {:?}", pub_key_hash.to_string());
    Identity::new(IdentityFlag::Ckb, pub_key_hash)
}

fn new_outpoint(tx_id: &str, index: u32) -> OutPoint {
    let tx_hash = H256::from_slice(&hex::decode(tx_id).unwrap())
        .unwrap()
        .pack();
    OutPoint::new(tx_hash, index)
}

fn new_record_id(tx_id: &str, index: u32, address: &str) -> RecordId {
    encode_record_id(
        new_outpoint(tx_id, index),
        AddressOrLockHash::Address(address.to_string()),
    )
}

#[test]
async fn test_record_id() {
    let record_id = new_record_id_2(
        "ecfea4bdf6bf8290d8f8186ed9f4da9b0f8fbba217600b47632f5a72ff677d4d",
        0,
        "52cea1b78b0240f21c1c94af84ce73420c2e9632",
    );
    println!("encode {:?}", hex::encode(record_id.to_vec()));
}

#[test]
async fn test_record_id_2() {
    let record_id = new_record_id_2(
        "ecfea4bdf6bf8290d8f8186ed9f4da9b0f8fbba217600b47632f5a72ff677d4d",
        0,
        "b4266453b38fae3503f05f2a6bd17e4967f15625",
    );
    println!("encode {:?}", hex::encode(record_id.to_vec()));
    let (outpoint, add) = decode_record_id(record_id).unwrap();
    println!("tx_id: {}", outpoint.tx_hash().to_string());
    println!("index: {}", outpoint.index());
    println!("lock_hash: {:?}", add);
}

fn new_record_id_2(tx_id: &str, index: u32, lock_hash: &str) -> RecordId {
    encode_record_id(
        new_outpoint(tx_id, index),
        AddressOrLockHash::LockHash(lock_hash.to_string()),
    )
}

async fn init_tip(rpc: &MercuryRpcImpl<CkbRpcClient>, tip_block_number: Option<BlockNumber>) {
    let tip_block_number = if let Some(tip_block_number) = tip_block_number {
        tip_block_number
    } else {
        let tip = rpc.inner_get_tip().await.unwrap().unwrap();
        tip.block_number.into()
    };
    let tip_epoch_number = rpc.get_epoch_by_number(tip_block_number).await.unwrap();
    CURRENT_BLOCK_NUMBER.swap(Arc::new(tip_block_number));
    CURRENT_EPOCH_NUMBER.swap(Arc::new(tip_epoch_number));
}

fn print_scripts(rpc: &MercuryRpcImpl<CkbRpcClient>, scripts: Vec<Script>) {
    for script in scripts {
        let address = rpc.script_to_address(&script);
        println!("{}", address.to_string());
    }
}

fn print_cells(rpc: &MercuryRpcImpl<CkbRpcClient>, cells: Vec<DetailedCell>) {
    for cell in cells {
        println!("*****************");
        println!("tx_hash: {}", cell.out_point.tx_hash().to_string());
        println!("output_index: {}", cell.out_point.index());
        println!("cell_output: {}", cell.cell_output);
        println!("cell_data: {}", hex::encode(cell.cell_data));
        println!(
            "address: {}",
            rpc.script_to_address(&cell.cell_output.lock()).to_string()
        );
    }
}

fn print_balances(balances: Vec<Balance>) {
    for balance in balances {
        println!("address_or_lock_hash: {:?}", balance.address_or_lock_hash);
        println!("asset_type: {:?}", balance.asset_info.asset_type);
        println!("udt_hash: {:?}", balance.asset_info.udt_hash.to_string());
        println!(
            "free: {}, occupied: {}, freezed: {}, claimable: {}",
            balance.free, balance.occupied, balance.freezed, balance.claimable
        );
        println!(
            "total: {}",
            balance.free.parse::<u128>().unwrap()
                + balance.occupied.parse::<u128>().unwrap()
                + balance.freezed.parse::<u128>().unwrap()
                + balance.claimable.parse::<u128>().unwrap()
        );
    }
}

fn print_block_info(block_info: BlockInfo) {
    println!("block_number: {}", block_info.block_number);
    println!("block_hash: {}", block_info.block_hash);
    print_transaction_infos(block_info.transactions);
}

fn print_transaction_infos(transaction_infos: Vec<TransactionInfo>) {
    for transaction in transaction_infos {
        println!("******************");
        println!("tx_hash: {}", transaction.tx_hash);
        println!("fee: {}", transaction.fee);
        println!("burn: {:?}", transaction.burn);
        print_records(transaction.records);
    }
}

fn print_records(records: Vec<Record>) {
    for record in records {
        println!("#################");
        println!("block_number: {}", record.block_number);
        println!("occupied: {}", record.occupied);
        println!("asset_type: {:?}", record.asset_info.asset_type);
        println!("udt_hash: {}", record.asset_info.udt_hash.to_string());
        println!("address_or_lock_hash: {:?}", record.address_or_lock_hash);
        println!("status: {:?}", record.status);
        println!("extra: {:?}", record.extra);
    }
}

async fn pretty_print_raw_tx(
    net_ty: NetworkType,
    rpc: &MercuryRpcImpl<CkbRpcClient>,
    raw_transaction: TransactionCompletionResponse,
) {
    let json_string = serde_json::to_string_pretty(&raw_transaction).unwrap();
    std::fs::write("tx.json", json_string.clone()).unwrap();

    let inputs = raw_transaction.tx_view.inner.inputs;
    println!("input shows");
    for input in inputs {
        let tx_hash = input.previous_output.tx_hash;
        let index: u32 = input.previous_output.index.into();
        let transaction = rpc.inner_get_transaction_view(tx_hash).await.unwrap();
        let output_cell = transaction.output(index as usize).unwrap();
        let data = transaction.outputs_data().get(index as usize).unwrap();
        print_cell_output(net_ty, output_cell.into(), data);
    }

    let outputs = raw_transaction.tx_view.inner.outputs;
    let data = raw_transaction.tx_view.inner.outputs_data;
    println!("output shows");
    for index in 0..outputs.len() {
        print_cell_output(net_ty, outputs[index].clone(), data[index].clone().into());
    }
}

fn print_cell_output(net_ty: NetworkType, output_cell: CellOutput, data: Bytes) {
    let payload = AddressPayload::from_script(&output_cell.lock.into(), net_ty.clone());
    let address = Address::new(net_ty, payload);
    let ckb_amount = output_cell.capacity.value();
    let udt_amount = decode_udt_amount(&data.as_slice()[4..]);
    println!(
        "address: {:?}, ckb_amount: {}, udt_amount: {}",
        address.to_string(),
        ckb_amount,
        udt_amount
    );
}

#[test]
async fn test_get_scripts_by_identity() {
    let rpc = new_rpc(NetworkType::Testnet).await;
    let identity = new_identity("ckt1qyqg3lvz8c8k7llaw8pzxjphkygfrllumymquvc562");
    let scripts = rpc.get_scripts_by_identity(identity, None).await.unwrap();
    print_scripts(&rpc, scripts);
}

#[test]
async fn test_get_scripts_by_address() {}

#[test]
async fn test_get_secp_address_by_item() {}

#[test]
async fn test_get_live_cells_by_identity() {
    let rpc = new_rpc(NetworkType::Testnet).await;
    let identity = new_identity("ckt1qyqg3lvz8c8k7llaw8pzxjphkygfrllumymquvc562");
    let cells = rpc
        .get_live_cells_by_item(
            Item::Identity(identity),
            HashSet::new(),
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .unwrap();
    print_cells(&rpc, cells);
}

#[test]
async fn test_get_live_cells_by_address() {
    let rpc = new_rpc(NetworkType::Testnet).await;
    let cells = rpc
        .get_live_cells_by_item(
            Item::Address("ckt1qyq8jy6e6hu89lzwwgv9qdx6p0kttl4uax9s79m0mr".to_string()),
            HashSet::new(),
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .unwrap();
    print_cells(&rpc, cells);
}

#[test]
async fn test_get_live_cells_by_record_id() {
    let rpc = new_rpc(NetworkType::Testnet).await;
    let record_id = new_record_id(
        "5ffcd5b3cbe73bd0237bd1ba8d6198228cb28c3a9d532967939890172b2d5904",
        0,
        "ckt1qyq8jy6e6hu89lzwwgv9qdx6p0kttl4uax9s79m0mr",
    );
    let cells = rpc
        .get_live_cells_by_item(
            Item::Record(record_id),
            HashSet::new(),
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .unwrap();
    print_cells(&rpc, cells);
}

#[test]
async fn test_get_live_cells_by_record_id_lock_hash() {
    let rpc = new_rpc(NetworkType::Testnet).await;
    // init_tip(&rpc, None).await;
    let record_id = new_record_id_2(
        "52b1cf0ad857d53e1a3552944c1acf268f6a6aea8e8fc85fe8febcb8127d56f0",
        0,
        "772dcc93612464ae31d0854a022091ea18bfc5ee",
    );

    let cells = rpc
        .get_live_cells_by_item(
            Item::Record(record_id),
            HashSet::new(),
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .unwrap();
    print_cells(&rpc, cells);
}

#[test]
async fn test_get_transactions_by_item() {}

#[test]
async fn test_get_secp_lock_hash_by_item() {}

#[test]
async fn test_to_record() {}

#[test]
async fn test_generate_ckb_address_or_lock_hash() {}

#[test]
async fn test_get_balance_by_address() {
    let rpc = new_rpc(NetworkType::Testnet).await;
    init_tip(&rpc, None).await;
    let item = JsonItem::Address("ckt1qypyfy67hjrqmcyzs2cpvdfhd9lx6mgc68aqjx5d7w".to_string());
    let asset_infos = HashSet::new();
    let payload = GetBalancePayload {
        item,
        asset_infos,
        tip_block_number: None,
    };
    let balances = rpc.inner_get_balance(payload).await;
    print_balances(balances.unwrap().balances);
}

#[test]
async fn test_get_balance_by_identity() {
    let rpc = new_rpc(NetworkType::Testnet).await;
    init_tip(&rpc, None).await;

    let identity = new_identity("ckt1qyq8jy6e6hu89lzwwgv9qdx6p0kttl4uax9s79m0mr");
    let item = JsonItem::Identity(hex::encode(identity.0));
    let asset_infos = HashSet::new();
    let payload = GetBalancePayload {
        item,
        asset_infos,
        tip_block_number: None,
    };
    let balances = rpc.inner_get_balance(payload).await;
    print_balances(balances.unwrap().balances);
}

#[test]
async fn test_get_balance_by_record_id() {
    let rpc = new_rpc(NetworkType::Testnet).await;
    init_tip(&rpc, None).await;

    let record_id = new_record_id_2(
        "ecfea4bdf6bf8290d8f8186ed9f4da9b0f8fbba217600b47632f5a72ff677d4d",
        0,
        "57f5d5f9a9cf8d1aafcef1513f6a11bb902840b8",
    );
    let item = JsonItem::Record(hex::encode(record_id.to_vec()));
    let asset_infos = HashSet::new();
    let payload = GetBalancePayload {
        item,
        asset_infos,
        tip_block_number: None,
    };
    let balances = rpc.inner_get_balance(payload).await;
    print_balances(balances.unwrap().balances);
}

#[test]
async fn test_get_balance_with_dao_deposit() {
    let rpc = new_rpc(NetworkType::Mainnet).await;
    init_tip(&rpc, None).await;

    let item = JsonItem::Address("ckb1qyq9r0aky9z8qh5t4y665lz2a6djm03kky0s5pp24p".to_string());
    let asset_infos = HashSet::new();
    let payload = GetBalancePayload {
        item,
        asset_infos,
        tip_block_number: None,
    };
    let balances = rpc.inner_get_balance(payload).await;
    print_balances(balances.unwrap().balances);
}

// select encode(tx_hash, 'hex'), encode(data, 'hex') from mercury_live_cell where type_code_hash = decode('82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e', 'hex') and data != decode('0000000000000000', 'hex') and lock_code_hash = decode('9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8', 'hex');
#[test]
async fn test_get_balance_with_dao_withdraw() {
    let rpc = new_rpc(NetworkType::Mainnet).await;
    init_tip(&rpc, None).await;

    let item = JsonItem::Address("ckb1qyqyh3cx7s2q0wpxhjc8a6kdzy8u043sk35s6jvqvv".to_string());
    let asset_infos = HashSet::new();
    let payload = GetBalancePayload {
        item,
        asset_infos,
        tip_block_number: None,
    };
    let balances = rpc.inner_get_balance(payload).await;
    print_balances(balances.unwrap().balances);
}

#[test]
async fn test_get_balance_with_cellbase() {
    let rpc = new_rpc(NetworkType::Mainnet).await;
    init_tip(&rpc, None).await;

    let item = JsonItem::Address("ckb1qyqdmeuqrsrnm7e5vnrmruzmsp4m9wacf6vsxasryq".to_string());
    let asset_infos = HashSet::new();
    let payload = GetBalancePayload {
        item,
        asset_infos,
        tip_block_number: None,
    };
    let balances = rpc.inner_get_balance(payload).await;
    print_balances(balances.unwrap().balances);
}

// 1000000  free: 1787576205864567, occupied: 114850800000000, freezed: 428435038890948, claimable: 0  total: 2330862044755515
#[test]
async fn test_get_history_balance_with_cellbase() {
    let tip_block_number = 1000000;

    let rpc = new_rpc(NetworkType::Mainnet).await;
    init_tip(&rpc, Some(tip_block_number)).await;

    let item = JsonItem::Address("ckb1qyqdmeuqrsrnm7e5vnrmruzmsp4m9wacf6vsxasryq".to_string());
    let asset_infos = HashSet::new();
    let payload = GetBalancePayload {
        item,
        asset_infos,
        tip_block_number: Some(tip_block_number),
    };
    let balances = rpc.inner_get_balance(payload).await;
    print_balances(balances.unwrap().balances);
}

// 4853527
#[test]
async fn test_get_history_balance() {
    let tip_block_number = 4853527;

    let rpc = new_rpc(NetworkType::Mainnet).await;
    init_tip(&rpc, Some(tip_block_number)).await;

    let item = JsonItem::Address("ckb1qyqqp5ayr86z8txza8n3g2k6ua7430y45qrqgrq786".to_string());
    let asset_infos = HashSet::new();
    let payload = GetBalancePayload {
        item,
        asset_infos,
        tip_block_number: Some(tip_block_number),
    };
    let balances = rpc.inner_get_balance(payload).await;
    print_balances(balances.unwrap().balances);
}

#[test]
async fn test_get_epoch_from_number() {
    let engine = RpcTestEngine::new_pg(NetworkType::Mainnet, MAINNET_PG_HOST).await;
    let rpc = engine.rpc(NetworkType::Mainnet);

    let block_number = 5364736;
    let epoch_number = rpc.get_epoch_by_number(block_number).await;
    println!("epoch_number: {:?}", epoch_number);
}

#[test]
async fn test_get_block_info_of_tip() {
    let rpc = new_rpc(NetworkType::Mainnet).await;
    init_tip(&rpc, None).await;

    let payload = GetBlockInfoPayload {
        block_number: None,
        block_hash: None,
    };
    let block_info = rpc.inner_get_block_info(payload).await.unwrap();
    print_block_info(block_info);
}

#[test]
async fn test_get_block_info_of_block_number() {
    let rpc = new_rpc(NetworkType::Mainnet).await;

    let payload = GetBlockInfoPayload {
        block_number: Some(5369644),
        block_hash: None,
    };
    let block_info = rpc.inner_get_block_info(payload).await.unwrap();
    print_block_info(block_info);
}

#[test]
async fn test_get_block_info_of_block_hash() {
    let rpc = new_rpc(NetworkType::Mainnet).await;

    let payload = GetBlockInfoPayload {
        block_number: None,
        block_hash: Some(
            H256::from_str("9a1f2ebe4644978e003c6c8ed16684426fb67c176a23db696d09d220c1d6eaf8")
                .unwrap(),
        ),
    };
    let block_info = rpc.inner_get_block_info(payload).await.unwrap();
    print_block_info(block_info);
}

#[test]
async fn test_get_transaction_info_of_dao() {
    let rpc = new_rpc(NetworkType::Mainnet).await;

    let tx_hash =
        H256::from_str("4db90d39520c59481c434c83e9f9bd1435f7da8df67015fd8fff2a8b08d14fba").unwrap();
    let transaction = rpc.inner_get_transaction_info(tx_hash).await.unwrap();
    print_transaction_infos(vec![transaction.transaction.unwrap()]);
}

#[test]
async fn test_get_transaction_info_of_dao_claim() {
    let rpc = new_rpc(NetworkType::Mainnet).await;

    let tx_hash =
        H256::from_str("3e08cbe01920ffc615a0a7cd89292d2ae1d77fedf23e639a84f44967cdcd1798").unwrap();
    let transaction = rpc.inner_get_transaction_info(tx_hash).await.unwrap();
    print_transaction_infos(vec![transaction.transaction.unwrap()]);
}

#[test]
async fn test_get_transaction_info_of_cell_base() {
    let rpc = new_rpc(NetworkType::Mainnet).await;

    let tx_hash =
        H256::from_str("5c1762e5fea2fd59c98dc483aaecac9fc5fdc7402e018aa973437661314aaedb").unwrap();
    let transaction = rpc.inner_get_transaction_info(tx_hash).await.unwrap();
    print_transaction_infos(vec![transaction.transaction.unwrap()]);
}

#[test]
async fn test_get_transaction_info_of_udt_mint() {
    let rpc = new_rpc(NetworkType::Mainnet).await;

    let tx_hash =
        H256::from_str("c219650853268e6948e51c053eca2e3f408668aa86b32856c996f2a6653d4dc1").unwrap();
    let transaction = rpc.inner_get_transaction_info(tx_hash).await.unwrap();
    print_transaction_infos(vec![transaction.transaction.unwrap()]);
}

#[test]
async fn test_get_transaction_info() {
    let rpc = new_rpc(NetworkType::Testnet).await;

    let tx_hash =
        H256::from_str("4329e4c751c95384a51072d4cbc9911a101fd08fc32c687353d016bf38b8b22c").unwrap();
    let transaction = rpc.inner_get_transaction_info(tx_hash).await.unwrap();
    print_transaction_infos(vec![transaction.transaction.unwrap()]);
}

#[test]
async fn test_get_spent_transaction_with_double_entry() {
    let rpc = new_rpc(NetworkType::Mainnet).await;

    let payload = GetSpentTransactionPayload {
        outpoint: new_outpoint(
            "244cc8e21f155562891eb2731b1c27e47d307e657b7be9630119eb724bbaec1c",
            1,
        )
        .into(),
        structure_type: StructureType::DoubleEntry,
    };

    let transaction = rpc.inner_get_spent_transaction(payload).await.unwrap();
    println!("transaction: {:?}", transaction);
}

#[test]
async fn test_get_spent_transaction_with_native_type() {
    let rpc = new_rpc(NetworkType::Mainnet).await;

    let payload = GetSpentTransactionPayload {
        outpoint: new_outpoint(
            "244cc8e21f155562891eb2731b1c27e47d307e657b7be9630119eb724bbaec1c",
            1,
        )
        .into(),
        structure_type: StructureType::Native,
    };

    let transaction = rpc.inner_get_spent_transaction(payload).await.unwrap();
    println!("transaction: {:?}", transaction);
}

#[test]
async fn test_build_deposit() {
    let net_ty = NetworkType::Mainnet;
    let rpc = new_rpc(net_ty.clone()).await;

    let items = vec![JsonItem::Address(
        "ckb1qyqgf9tl0ecx6an7msqllp0jfe99j64qtwcqhfsug7".to_string(),
    )];
    let payload = DepositPayload {
        from: From2 {
            items,
            source: Source::Free,
        },
        to: None,
        amount: 200_00000000,
        fee_rate: None,
    };

    let raw_transaction = rpc.inner_build_deposit_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

// select encode(tx_hash, 'hex') from mercury_live_cell where type_code_hash = decode('82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e', 'hex') and data != decode('0000000000000000', 'hex') limit 10;
#[test]
async fn test_build_withdraw() {
    let net_ty = NetworkType::Mainnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let items = JsonItem::Address("ckb1qyqdnwp9xvkukg3jxsh07ww99tlw7m7ttg6qfcatz0".to_string());
    let pay_fee = "ckb1qyqgf9tl0ecx6an7msqllp0jfe99j64qtwcqhfsug7".to_string();
    let payload = WithdrawPayload {
        from: items,
        pay_fee: Some(pay_fee),
        fee_rate: None,
    };

    let raw_transaction = rpc.inner_build_withdraw_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

#[test]
async fn test_build_transfer_with_ckb_and_hold_by_from() {
    let net_ty = NetworkType::Mainnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_ckb();
    let items = vec![JsonItem::Address(
        "ckb1qyqgf9tl0ecx6an7msqllp0jfe99j64qtwcqhfsug7".to_string(),
    )];
    let to_info = ToInfo {
        address: "ckb1qyqdnwp9xvkukg3jxsh07ww99tlw7m7ttg6qfcatz0".to_string(),
        amount: "96500000000".to_string(),
    };
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByFrom,
        },
        pay_fee: None,
        change: None,
        fee_rate: None,
        since: None,
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

#[test]
async fn test_build_transfer_with_ckb_and_hold_by_from_with_since() {
    let net_ty = NetworkType::Mainnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_ckb();
    let items = vec![JsonItem::Address(
        "ckb1qyqgf9tl0ecx6an7msqllp0jfe99j64qtwcqhfsug7".to_string(),
    )];
    let to_info = ToInfo {
        address: "ckb1qyqdnwp9xvkukg3jxsh07ww99tlw7m7ttg6qfcatz0".to_string(),
        amount: "96500000000".to_string(),
    };
    let since = SinceConfig {
        flag: SinceFlag::Absolute,
        type_: SinceType::BlockNumber,
        value: 6000000,
    };
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByFrom,
        },
        pay_fee: None,
        change: None,
        fee_rate: None,
        since: Some(since),
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

#[test]
async fn test_build_transfer_with_ckb_and_hold_by_from_with_change() {
    let net_ty = NetworkType::Mainnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_ckb();
    let items = vec![JsonItem::Address(
        "ckb1qyqgf9tl0ecx6an7msqllp0jfe99j64qtwcqhfsug7".to_string(),
    )];
    let to_info = ToInfo {
        address: "ckb1qyqdnwp9xvkukg3jxsh07ww99tlw7m7ttg6qfcatz0".to_string(),
        amount: "96500000000".to_string(),
    };
    let change = "ckb1qyqqzgqrcs0dfwurn8cwgpdd4e5vke5hrxjq6ns3sq".to_string();
    let since = SinceConfig {
        flag: SinceFlag::Absolute,
        type_: SinceType::BlockNumber,
        value: 6000000,
    };
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByFrom,
        },
        pay_fee: None,
        change: Some(change),
        fee_rate: None,
        since: Some(since),
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

#[test]
async fn test_build_transfer_with_ckb_and_hold_by_from_with_pay_fee() {
    let net_ty = NetworkType::Mainnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_ckb();
    let items = vec![JsonItem::Address(
        "ckb1qyqgf9tl0ecx6an7msqllp0jfe99j64qtwcqhfsug7".to_string(),
    )];
    let to_info = ToInfo {
        address: "ckb1qyqdnwp9xvkukg3jxsh07ww99tlw7m7ttg6qfcatz0".to_string(),
        amount: "96500000000".to_string(),
    };
    let change = "ckb1qyqqzgqrcs0dfwurn8cwgpdd4e5vke5hrxjq6ns3sq".to_string();
    let pay_fee = "ckb1qyqqzgqrcs0dfwurn8cwgpdd4e5vke5hrxjq6ns3sq".to_string();
    let since = SinceConfig {
        flag: SinceFlag::Absolute,
        type_: SinceType::BlockNumber,
        value: 6000000,
    };
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByFrom,
        },
        pay_fee: Some(pay_fee),
        change: Some(change),
        fee_rate: None,
        since: Some(since),
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

#[test]
async fn test_build_transfer_with_ckb_and_hold_by_from_with_fee_rate() {
    let net_ty = NetworkType::Mainnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_ckb();
    let items = vec![JsonItem::Address(
        "ckb1qyqgf9tl0ecx6an7msqllp0jfe99j64qtwcqhfsug7".to_string(),
    )];
    let to_info = ToInfo {
        address: "ckb1qyqdnwp9xvkukg3jxsh07ww99tlw7m7ttg6qfcatz0".to_string(),
        amount: "96500000000".to_string(),
    };
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByFrom,
        },
        pay_fee: None,
        change: None,
        fee_rate: Some(1000000),
        since: None,
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

// ckb acp cell -- tx_hash: d57e1b000b3abaf90a04fdb1be2b2f5e1882b77b77cdf0161553b99e346c4175, index: 0, capacity: 67.99996356
#[test]
async fn test_build_transfer_with_ckb_and_hold_by_to_with_pay_fee() {
    let net_ty = NetworkType::Mainnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_ckb();
    let items = vec![JsonItem::Address(
        "ckb1qyqgf9tl0ecx6an7msqllp0jfe99j64qtwcqhfsug7".to_string(),
    )];
    let to_info = ToInfo {
        address: "ckb1qypvd79a2xjder5xqx5crvrtq07ca3d55qqs95l0n8".to_string(),
        amount: "96500000000".to_string(),
    };
    let change = "ckb1qyqqzgqrcs0dfwurn8cwgpdd4e5vke5hrxjq6ns3sq".to_string();
    let pay_fee = "ckb1qyqy5vmywpty6p72wpvm0xqys8pdtxqf6cmsr8p2l0".to_string();
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByTo,
        },
        pay_fee: Some(pay_fee),
        change: Some(change),
        fee_rate: None,
        since: None,
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

#[test]
async fn test_build_transfer_with_ckb_and_hold_by_to() {
    let net_ty = NetworkType::Mainnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_ckb();
    let items = vec![JsonItem::Address(
        "ckb1qyqgf9tl0ecx6an7msqllp0jfe99j64qtwcqhfsug7".to_string(),
    )];
    let to_info = ToInfo {
        address: "ckb1qypvd79a2xjder5xqx5crvrtq07ca3d55qqs95l0n8".to_string(),
        amount: "96500000000".to_string(),
    };
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByTo,
        },
        pay_fee: None,
        change: None,
        fee_rate: None,
        since: None,
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

#[test]
async fn test_build_transfer_with_udt_and_hold_by_from() {
    let net_ty = NetworkType::Testnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_udt(
        H256::from_str("f21e7350fa9518ed3cbb008e0e8c941d7e01a12181931d5608aa366ee22228bd").unwrap(),
    );
    let identity = new_identity("ckt1qyq8jy6e6hu89lzwwgv9qdx6p0kttl4uax9s79m0mr");
    let item = JsonItem::Identity(hex::encode(identity.0));
    let items = vec![item.into()];
    let to_info = ToInfo {
        address: "ckt1qyqv2w7f5kuctnt03kk9l09gwuuy6wpys64s4f8vve".to_string(),
        amount: "1111".to_string(),
    };
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByFrom,
        },
        pay_fee: None,
        change: None,
        fee_rate: None,
        since: None,
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

#[test]
async fn test_build_transfer_with_udt_and_hold_by_from_with_pay_fee() {
    let net_ty = NetworkType::Testnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_udt(
        H256::from_str("f21e7350fa9518ed3cbb008e0e8c941d7e01a12181931d5608aa366ee22228bd").unwrap(),
    );
    let identity = new_identity("ckt1qyq8jy6e6hu89lzwwgv9qdx6p0kttl4uax9s79m0mr");
    let item = JsonItem::Identity(hex::encode(identity.0));
    let items = vec![item.into()];
    let to_info = ToInfo {
        address: "ckt1qyqv2w7f5kuctnt03kk9l09gwuuy6wpys64s4f8vve".to_string(),
        amount: "1111".to_string(),
    };
    let change = "ckt1qyqv2w7f5kuctnt03kk9l09gwuuy6wpys64s4f8vve".to_string();
    let pay_fee = "ckt1qyqyfy67hjrqmcyzs2cpvdfhd9lx6mgc68aqukw69v".to_string();
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByFrom,
        },
        pay_fee: Some(pay_fee),
        change: Some(change),
        fee_rate: None,
        since: None,
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

#[test]
async fn test_build_transfer_with_udt_and_hold_by_to() {
    let net_ty = NetworkType::Testnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_udt(
        H256::from_str("f21e7350fa9518ed3cbb008e0e8c941d7e01a12181931d5608aa366ee22228bd").unwrap(),
    );
    let identity = new_identity("ckt1qyq8jy6e6hu89lzwwgv9qdx6p0kttl4uax9s79m0mr");
    let item = JsonItem::Identity(hex::encode(identity.0));
    let items = vec![item.into()];
    let to_info = ToInfo {
        address: "ckt1qypv2w7f5kuctnt03kk9l09gwuuy6wpys64smeamhm".to_string(),
        amount: "1111".to_string(),
    };
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByTo,
        },
        pay_fee: None,
        change: None,
        fee_rate: None,
        since: None,
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

#[test]
async fn test_build_transfer_with_udt_and_hold_by_to_with_pay_fee() {
    let net_ty = NetworkType::Testnet;
    let rpc = new_rpc(net_ty.clone()).await;
    init_tip(&rpc, None).await;

    let asset_info = AssetInfo::new_udt(
        H256::from_str("f21e7350fa9518ed3cbb008e0e8c941d7e01a12181931d5608aa366ee22228bd").unwrap(),
    );
    let identity = new_identity("ckt1qyq8jy6e6hu89lzwwgv9qdx6p0kttl4uax9s79m0mr");
    let item = JsonItem::Identity(hex::encode(identity.0));
    let items = vec![item.into()];
    let to_info = ToInfo {
        address: "ckt1qypv2w7f5kuctnt03kk9l09gwuuy6wpys64smeamhm".to_string(),
        amount: "1111".to_string(),
    };
    let change = "ckt1qyqv2w7f5kuctnt03kk9l09gwuuy6wpys64s4f8vve".to_string();
    let pay_fee = "ckt1qyqyfy67hjrqmcyzs2cpvdfhd9lx6mgc68aqukw69v".to_string();
    let payload = TransferPayload {
        asset_info,
        from: From2 {
            items,
            source: Source::Free,
        },
        to: To {
            to_infos: vec![to_info],
            mode: Mode::HoldByTo,
        },
        pay_fee: Some(pay_fee),
        change: Some(change),
        fee_rate: None,
        since: None,
    };

    let raw_transaction = rpc.inner_build_transfer_transaction(payload).await.unwrap();
    pretty_print_raw_tx(net_ty, &rpc, raw_transaction).await;
}

// {"item":{"Identity":"0x001a4ff63598e43af9cd42324abb7657fa849c5bc3"},"asset_infos":[],
// "block_range":{"from":2778109,"to":2778110},"pagination":{"order":"desc","limit":50,"return_count":false}}
// 0x5d1ca3166fe6a289bdbbf5cdeb36407ea767a5ebbae6ffb413feaa53fcdf538f
// 0x1a4ff63598e43af9cd42324abb7657fa849c5bc3
#[test]
async fn test_query_transactions() {
    let net_ty = NetworkType::Testnet;
    let rpc = new_rpc(net_ty.clone()).await;

    let payload = QueryTr
    let transactions = rpc.inner_query_transaction().await.unwrap();

}
