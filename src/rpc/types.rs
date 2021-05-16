use crate::rpc::rpc_impl::SMT;

use ckb_indexer::indexer::DetailedLiveCell;
use ckb_types::packed;
use serde::{Deserialize, Serialize};

pub const WHITE_BLACK_LIST_MASK: u8 = 0x2;
pub const EMERGENCY_HALT_MODE_MASK: u8 = 0x1;

#[derive(Clone, Debug)]
pub enum RCState {
    WhiteList,
    BlackList,
    Halt,
}

impl From<packed::Byte> for RCState {
    fn from(byte: packed::Byte) -> Self {
        let s: u8 = byte.into();

        if s & EMERGENCY_HALT_MODE_MASK == EMERGENCY_HALT_MODE_MASK {
            return RCState::Halt;
        }

        if s & WHITE_BLACK_LIST_MASK == WHITE_BLACK_LIST_MASK {
            RCState::WhiteList
        } else {
            RCState::BlackList
        }
    }
}

pub struct InnerRCRule {
    pub kind: RCState,
    pub smt: SMT,
}

impl InnerRCRule {
    pub fn new(kind: RCState, smt: SMT) -> Self {
        InnerRCRule { kind, smt }
    }
}

pub struct RCECellPair {
    pub index: usize,
    pub input: DetailedLiveCell,
    pub output: packed::CellOutput,
}

impl Default for RCECellPair {
    fn default() -> Self {
        RCECellPair {
            index: Default::default(),
            input: DetailedLiveCell {
                block_number: Default::default(),
                block_hash: Default::default(),
                tx_index: Default::default(),
                cell_data: Default::default(),
                cell_output: Default::default(),
            },
            output: Default::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SMTUpdateItem {
    pub key: ckb_types::H256,
    pub new_val: u8,
}
