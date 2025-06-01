use std::str::FromStr;

use bitcoin::{
    absolute::LockTime, transaction::Version, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};

use crate::types::UTXO;

const DUST_THRESHOLD: u64 = 546;
// Constants for input vsize
pub const P2WPKH_INPUT_VBYTES: u64 = 68; // SegWit native input
pub const P2SH_P2WPKH_INPUT_VBYTES: u64 = 91; // Wrapped SegWit input
pub const P2PKH_INPUT_VBYTES: u64 = 148; // Legacy input
pub const P2TR_INPUT_VBYTES: u64 = 112; // Taproot input

// Constants for output vsize
pub const P2WPKH_OUTPUT_VBYTES: u64 = 31; // SegWit native output
pub const P2PKH_OUTPUT_VBYTES: u64 = 34; // Legacy output
pub const P2TR_OUTPUT_VBYTES: u64 = 43; // Taproot output

// Optional overhead
pub const TX_OVERHEAD_VBYTES: u64 = 10; // Version, locktime, marker/flag, varints

pub enum ScriptType {
    P2WPKH,
    P2SH_P2WPKH,
    P2PKH,
    P2TR,
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransactionBuilderError {
    #[error("Insufficient funds: need {required}, have {available}")]
    InsufficientFunds { required: u64, available: u64 },

    #[error("Invalid TXID format: {txid}")]
    InvalidTxid { txid: String },

    #[error("Output value {value} is below dust threshold {threshold}")]
    DustOutput { value: u64, threshold: u64 },

    #[error("Transaction too large: {size} bytes exceeds limit")]
    TransactionTooLarge { size: usize },

    #[error("No inputs provided")]
    NoInputs,

    #[error("No outputs provided")]
    NoOutputs,

    #[error("Invalid fee rate: {fee_rate}")]
    InvalidFeeRate { fee_rate: u64 },

    #[error("Signing failed for input {input_index}: {reason}")]
    SigningError { input_index: usize, reason: String },

    #[error("Bitcoin library error: {0}")]
    BitcoinError(#[from] bitcoin::consensus::encode::Error),

    #[error("Hex decode error: {0}")]
    HexError(#[from] bitcoin::hex::HexToArrayError),
}

// Type alias for convenience
pub type Result<T> = std::result::Result<T, TransactionBuilderError>;

//todo: hold UTXOs rather than TxIn
pub struct TransactionBuilder {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub estimated_vsize: u64,
    pub change_script: ScriptBuf,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        TransactionBuilder {
            inputs: Vec::new(),
            outputs: Vec::new(),
            estimated_vsize: 0,
            change_script: ScriptBuf::new(),
        }
    }
}

impl TransactionBuilder {
    pub fn estimate_vsize(&self) -> Result<u64> {
        Ok(self.estimated_vsize)
    }

    pub fn add_input(&mut self, outpoint: UTXO, sequence: Sequence, script_type: ScriptType) {
        let input_vsize = match script_type {
            ScriptType::P2WPKH => P2WPKH_INPUT_VBYTES,
            ScriptType::P2SH_P2WPKH => P2SH_P2WPKH_INPUT_VBYTES,
            ScriptType::P2PKH => P2PKH_INPUT_VBYTES,
            ScriptType::P2TR => P2TR_INPUT_VBYTES,
        };

        let txin = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(&outpoint.txid).unwrap(),
                vout: outpoint.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: sequence,
            witness: Witness::new(),
        };

        self.estimated_vsize += input_vsize;
        self.inputs.push(txin);
    }

    pub fn add_output(&mut self, output: TxOut) {
        self.outputs.push(output);
    }

    pub fn set_fee_with_fee_rate(&mut self, fee_rate: u64) -> Result<()> {
        let tx_vsize = self.estimate_vsize()?;
        let calculated_fee = tx_vsize * fee_rate;

        let total_input: u64 = self
            .inputs
            .iter()
            .map(|txin| txin.previous_output.value)
            .sum();

        let total_output: u64 = self.outputs.iter().map(|txout| txout.value.to_sat()).sum();

        // Check if we have enough funds
        if total_input < total_output + calculated_fee {
            return Err(TransactionBuilderError::InsufficientFunds {
                required: total_input + calculated_fee,
                available: total_input,
            });
        }

        // Calculate change
        let change_amount = total_input - total_output - calculated_fee;

        // Add change output if above dust threshold
        if change_amount > DUST_THRESHOLD {
            self.outputs.push(TxOut {
                value: change_amount,
                script_pubkey: self.change_script.clone(),
            });
        }
        // If change is dust, it becomes additional fee

        Ok(())
    }
    pub fn sign(&mut self) {
        // init the sighash cache with tx
        // fetch prevouts for amounts
        // sighash_signer p2wpkh_hash_function to sign the inputs
        // push into the respective witness stack
    }

    pub fn build(&self) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: self.inputs.clone(),
            output: self.outputs.clone(),
        }
    }
}
