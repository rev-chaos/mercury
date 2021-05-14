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
