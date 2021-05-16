use crate::rpc::rpc_impl::SMT;

use ckb_types::packed;

#[derive(Clone, Debug)]
pub enum RCState {
    WhiteList,
    BlackList,
    Stop,
}

impl From<packed::Byte> for RCState {
    fn from(byte: packed::Byte) -> Self {
        let s: u8 = byte.into();

        if s & 0x1 == 0x1 {
            return RCState::Stop;
        }

        if s & 0x2 == 0x1 {
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
