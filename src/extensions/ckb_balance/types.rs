use crate::utils::to_fixed_array;

use ckb_indexer::store;
use ckb_types::{core::BlockNumber, packed, prelude::Entity};
use derive_more::Display;
use rlp::{Decodable, DecoderError, Encodable, Prototype, Rlp, RlpStream};

use std::collections::HashMap;

#[derive(Debug, Display)]
pub enum CkbBalanceExtensionError {
    #[display(fmt = "Ckb balance is negative {}, address {}", _1, _0)]
    BalanceIsNegative(String, i128),

    #[display(
        fmt = "Cannot get live cell by outpoint tx_hash {}, index {}",
        tx_hash,
        index
    )]
    NoLiveCellByOutpoint { tx_hash: String, index: u32 },

    #[display(fmt = "DB Error {}", _0)]
    DBError(String),
}

impl std::error::Error for CkbBalanceExtensionError {}

impl From<store::Error> for CkbBalanceExtensionError {
    fn from(err: store::Error) -> Self {
        CkbBalanceExtensionError::DBError(err.to_string())
    }
}

#[repr(u8)]
pub enum KeyPrefix {
    Address = 0,
    Block = 16,
}

#[derive(Clone, Debug)]
pub enum Key<'a> {
    CkbAddress(&'a [u8]),
    Block(BlockNumber, &'a packed::Byte32),
}

impl<'a> Into<Vec<u8>> for Key<'a> {
    fn into(self) -> Vec<u8> {
        let mut encoded = Vec::new();

        match self {
            Key::CkbAddress(key) => {
                encoded.push(KeyPrefix::Address as u8);
                encoded.extend_from_slice(key);
            }

            Key::Block(block_num, block_hash) => {
                encoded.push(KeyPrefix::Block as u8);
                encoded.extend_from_slice(&block_num.to_be_bytes());
                encoded.extend_from_slice(block_hash.as_slice());
            }
        }

        encoded
    }
}

impl<'a> Key<'a> {
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }
}

#[derive(Clone, Debug)]
pub enum Value {
    CkbBalance(u64),
    RollbackData(Vec<u8>),
}

impl Into<Vec<u8>> for Value {
    fn into(self) -> Vec<u8> {
        match self {
            Value::CkbBalance(balance) => Vec::from(balance.to_be_bytes()),
            Value::RollbackData(data) => data,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CkbDeltaBalance {
    addr: [u8; 32],
    balance: i128,
}

impl CkbDeltaBalance {
    fn new(addr: [u8; 32], balance: i128) -> Self {
        CkbDeltaBalance { addr, balance }
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::from(self.balance.to_le_bytes());
        ret.extend_from_slice(&self.addr);
        ret
    }
}

impl From<Vec<u8>> for CkbDeltaBalance {
    fn from(v: Vec<u8>) -> Self {
        let balance = i128::from_le_bytes(to_fixed_array(&v[0..16]));
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&v[16..48]);
        CkbDeltaBalance { addr, balance }
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct CkbBalanceMap(HashMap<[u8; 32], i128>);

impl Encodable for CkbBalanceMap {
    fn rlp_append(&self, s: &mut RlpStream) {
        let len = self.len();

        s.begin_list(len + 1);
        s.append(&len);

        self.0.iter().for_each(|(k, v)| {
            let delta = CkbDeltaBalance::new(*k, *v);
            s.append(&delta.as_bytes());
        });
    }
}

impl Decodable for CkbBalanceMap {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.prototype()? {
            Prototype::List(_) => {
                let len: usize = rlp.val_at(0)?;
                let mut map = HashMap::new();

                for i in 1..(len + 1) {
                    let bytes: Vec<u8> = rlp.val_at(i)?;
                    let delta = CkbDeltaBalance::from(bytes);
                    map.insert(delta.addr, delta.balance);
                }

                Ok(CkbBalanceMap::new(map))
            }

            _ => Err(DecoderError::Custom("invalid prototype")),
        }
    }
}

impl CkbBalanceMap {
    pub fn new(map: HashMap<[u8; 32], i128>) -> Self {
        CkbBalanceMap(map)
    }

    pub fn inner(&self) -> &HashMap<[u8; 32], i128> {
        &self.0
    }

    pub fn inner_mut(&mut self) -> &mut HashMap<[u8; 32], i128> {
        &mut self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn opposite_value(&mut self) {
        self.0.iter_mut().for_each(|(_k, v)| *v *= -1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    fn rand_byte32() -> [u8; 32] {
        let mut ret = [0u8; 32];
        ret.copy_from_slice(&(0..32).map(|_| random::<u8>()).collect::<Vec<_>>());
        ret
    }

    #[test]
    fn test_ckb_delta_balance_codec() {
        for _i in 0..10 {
            let addr = rand_byte32();
            let balance = random::<i128>();
            let delta = CkbDeltaBalance::new(addr, balance);

            let bytes = delta.as_bytes();
            assert_eq!(delta, CkbDeltaBalance::from(bytes));
        }
    }

    #[test]
    fn test_ckb_balance_map_codec() {
        for _i in 0..10 {
            let key_1 = rand_byte32();
            let val_1 = random::<i128>();
            let key_2 = rand_byte32();
            let val_2 = random::<i128>();

            let mut origin_map = CkbBalanceMap::default();
            let map = origin_map.inner_mut();

            map.insert(key_1, val_1);
            map.insert(key_2, val_2);

            let bytes = origin_map.rlp_bytes();
            assert_eq!(
                origin_map,
                CkbBalanceMap::decode(&Rlp::new(&bytes)).unwrap()
            );
        }
    }

    #[test]
    fn test_ckb_balance_map() {
        let key_1 = rand_byte32();
        let val_1 = random::<i128>();
        let key_2 = rand_byte32();
        let val_2 = random::<i128>();

        let mut origin_map = CkbBalanceMap::default();
        let map = origin_map.inner_mut();

        map.insert(key_1, val_1);
        map.insert(key_2, val_2);

        origin_map.opposite_value();
        let origin_clone = origin_map.clone();
        let map = origin_clone.inner();

        assert_eq!(origin_map.len(), 2);
        assert_eq!(*map.get(&key_1).unwrap(), (0 - val_1));
        assert_eq!(*map.get(&key_2).unwrap(), (0 - val_2));
    }
}
