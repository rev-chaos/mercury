use ckb_indexer::store::Error as StoreError;
use ckb_jsonrpc_types::OutPoint;
use derive_more::Display;
use smt::error::Error as SMTError;

#[derive(Debug, Display)]
pub enum MercuryError {
    #[display(fmt = "DB error: {:?}", _0)]
    DBError(String),

    #[display(fmt = "Parse CKB address error {:?}", _0)]
    ParseCKBAddressError(String),

    #[display(fmt = "Already a short CKB address")]
    _AlreadyShortCKBAddress,

    #[display(fmt = "Cannot find cell by out point {:?}", _0)]
    CannotFindCellByOutPoint(OutPoint),

    #[display(fmt = "Sparse merkle tree error {:?}", _0)]
    SMTError(String),

    #[display(fmt = "Output must be rce cell when update rce rule")]
    InvalidOutputCellWhenUpdateRCE,

    #[display(fmt = "Missing RC data")]
    MissingRCData,

    #[display(fmt = "The rce rule number {} is above 8196", _0)]
    RCRuleNumOverMax(usize),

    #[display(fmt = "Check white list failed, script hash {:?}", _0)]
    CheckWhiteListFailed(String),

    #[display(fmt = "Check black list failed, script hash {:?}", _0)]
    CheckBlackListFailed(String),

    #[display(fmt = "Rce rule is in stop state, root {:?}", _0)]
    RCRuleIsInStopState(String),
}

impl std::error::Error for MercuryError {}

impl From<StoreError> for MercuryError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::DBError(s) => MercuryError::DBError(s),
        }
    }
}

impl From<SMTError> for MercuryError {
    fn from(error: SMTError) -> Self {
        MercuryError::SMTError(error.to_string())
    }
}
