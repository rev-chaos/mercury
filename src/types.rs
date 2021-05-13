use crate::{extensions::ExtensionType, utils::blake2b_256};

use ckb_indexer::indexer::DetailedLiveCell;
use ckb_jsonrpc_types::{CellDep, Script};
use ckb_types::packed;
use serde::{Deserialize, Serialize};
use smt::{traits::Value, H256};

use std::collections::HashMap;

pub const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";
pub const BLANK_HASH: [u8; 32] = [
    68, 244, 198, 151, 68, 213, 248, 197, 93, 100, 32, 98, 148, 157, 202, 228, 155, 196, 231, 239,
    67, 211, 136, 197, 161, 47, 66, 181, 99, 61, 22, 62,
];

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub struct JsonDeployedScriptConfig {
    pub name: String,
    pub script: Script,
    pub cell_dep: CellDep,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct JsonExtensionsConfig {
    pub enabled_extensions: HashMap<ExtensionType, HashMap<String, JsonDeployedScriptConfig>>,
}

#[derive(Default, Clone, Debug)]
pub struct DeployedScriptConfig {
    pub name: String,
    pub script: packed::Script,
    pub cell_dep: packed::CellDep,
}

#[derive(Default, Clone, Debug)]
pub struct ExtensionsConfig {
    pub enabled_extensions: HashMap<ExtensionType, HashMap<String, DeployedScriptConfig>>,
}

impl From<JsonDeployedScriptConfig> for DeployedScriptConfig {
    fn from(json: JsonDeployedScriptConfig) -> DeployedScriptConfig {
        DeployedScriptConfig {
            name: json.name.clone(),
            script: json.script.into(),
            cell_dep: json.cell_dep.into(),
        }
    }
}

impl From<DeployedScriptConfig> for JsonDeployedScriptConfig {
    fn from(config: DeployedScriptConfig) -> JsonDeployedScriptConfig {
        JsonDeployedScriptConfig {
            name: config.name.clone(),
            script: config.script.into(),
            cell_dep: config.cell_dep.into(),
        }
    }
}

impl From<JsonExtensionsConfig> for ExtensionsConfig {
    fn from(json: JsonExtensionsConfig) -> ExtensionsConfig {
        ExtensionsConfig {
            enabled_extensions: json
                .enabled_extensions
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().map(|(k, v)| (k, v.into())).collect()))
                .collect(),
        }
    }
}

impl From<ExtensionsConfig> for JsonExtensionsConfig {
    fn from(config: ExtensionsConfig) -> JsonExtensionsConfig {
        JsonExtensionsConfig {
            enabled_extensions: config
                .enabled_extensions
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().map(|(k, v)| (k, v.into())).collect()))
                .collect(),
        }
    }
}

impl ExtensionsConfig {
    pub fn to_rpc_config(&self) -> HashMap<String, DeployedScriptConfig> {
        let mut ret = HashMap::new();

        for (_name, map) in self.enabled_extensions.iter() {
            map.iter().for_each(|(key, val)| {
                let _ = ret.insert(key.clone(), val.clone());
            });
        }
        ret
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

impl RCECellPair {
    // pub fn new(index: usize, input: DetailedLiveCell, output: packed::CellOutput) -> Self {
    //     RCECellPair {
    //         index,
    //         input,
    //         output,
    //     }
    // }

    pub fn set_index(&mut self, index: usize) {
        self.index = index;
    }

    pub fn set_input(&mut self, input: DetailedLiveCell) {
        self.input = input;
    }

    pub fn set_output(&mut self, output: packed::CellOutput) {
        self.output = output;
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SMTUpdateItem {
    pub key: ckb_types::H256,
    pub val: u8,
}

#[derive(Default, Clone, Debug)]
pub struct SMTValue([u8; 1]);

impl Value for SMTValue {
    fn to_h256(&self) -> H256 {
        blake2b_256(&self.0).into()
    }

    fn zero() -> Self {
        Default::default()
    }
}

impl From<u8> for SMTValue {
    fn from(s: u8) -> Self {
        SMTValue([s; 1])
    }
}
