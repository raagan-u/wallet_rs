use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize,Debug)]
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub status: UTXOStatus,
    pub value: u64
}

#[derive(Serialize, Deserialize,Debug)]
pub struct UTXOStatus {
    pub confirmed: bool,
    pub block_height: u32,
    pub block_hash: String,
    pub block_time: u64
}