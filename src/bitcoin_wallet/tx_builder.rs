use bitcoin::{absolute::LockTime, transaction::Version, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

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
    pub fn add_segwit_input(&mut self, outpoint: OutPoint, sequence: Sequence) {
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: sequence,
            witness: Witness::new()
        };
        self.inputs.push(txin);
    }

    pub fn add_output(&mut self, output: TxOut) {
        self.outputs.push(output);
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