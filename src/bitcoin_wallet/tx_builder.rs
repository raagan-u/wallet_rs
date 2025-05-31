use std::str::FromStr;

use bitcoin::{absolute::LockTime, transaction::Version, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::types::UTXO;

const DUST_THRESHOLD: u64 = 546;

//todo: hold UTXOs rather than TxIn
pub struct TransactionBuilder {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        TransactionBuilder {
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }
}

impl TransactionBuilder {
    pub fn estimate_vsize(&self) -> Result<u64, Error> {
        
        Ok(100)
    }
    
    pub fn add_input(&mut self, outpoint: UTXO, sequence: Sequence) {
        let txin = TxIn {
            previous_output: OutPoint { txid: Txid::from_str(&outpoint.txid).unwrap(), vout: outpoint.vout },
            script_sig: ScriptBuf::new(),
            sequence: sequence,
            witness: Witness::new()
        };
        self.inputs.push(txin);
    }

    pub fn add_output(&mut self, output: TxOut) {
        self.outputs.push(output);
    }

    pub fn set_fee_with_fee_rate(&mut self, fee_rate: u64) -> Result<(), Error> {
        // Calculate transaction size (you'll need to estimate/calculate vbytes)
        let tx_vsize = self.estimate_vsize()?;
        let calculated_fee = tx_vsize * fee_rate;
        
        let total_input: u64 = self.inputs.iter()
            .map(|txin| txin.previous_output.value)
            .sum();
        
        let total_output: u64 = self.outputs.iter()
            .map(|txout| txout.value)
            .sum();
        
        // Check if we have enough funds
        if total_input < total_output + calculated_fee {
            return Err(Error::InsufficientFunds);
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