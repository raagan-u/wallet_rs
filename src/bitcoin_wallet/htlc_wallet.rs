use anyhow::{anyhow, Result};
use bitcoin::{
    blockdata::transaction::{Transaction, TxIn, TxOut},
    ecdsa::Signature as BitcoinSignature,
    hashes::{hash160, sha256, Hash},
    key::Secp256k1,
    locktime::absolute::LockTime,
    network::Network,
    secp256k1::{self, Message, PublicKey, SecretKey},
    sighash::{EcdsaSighashType, SighashCache},
    taproot::LeafVersion,
    transaction::Version,
    Address, Amount, CompressedPublicKey, OutPoint, PrivateKey, Script, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Txid, Witness
};
use std::{collections::HashMap, str::FromStr};
use crate::bitcoin_wallet::htlc::{BitcoinHTLC, WrappedWitness};

pub struct HTLCWallet {
    secp: Secp256k1<secp256k1::All>,
    network: Network,
    private_key: SecretKey,
    public_key: PublicKey,
    address: Address,
    utxos: HashMap<OutPoint, TxOut>,
}

impl HTLCWallet {
    // Dust threshold constants (in satoshis)
    const P2WPKH_DUST_THRESHOLD: u64 = 294;
    const P2TR_DUST_THRESHOLD: u64 = 330;
    const DEFAULT_DUST_THRESHOLD: u64 = 546;

    pub fn new(private_key_str: &str, network: Network) -> Result<Self> {
        let secp = Secp256k1::new();
        let private_key = SecretKey::from_str(private_key_str)?;
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        let priv_key = PrivateKey::from_slice(&hex::decode(private_key_str)?, network)?;
        let compressed = CompressedPublicKey::from_private_key(&secp, &priv_key)?;
        let address = Address::p2wpkh(&compressed, network);
        
        Ok(Self {
            secp,
            network,
            private_key,
            public_key,
            address,
            utxos: HashMap::new(),
        })
    }

    pub fn get_address(&self) -> Address {
        self.address.clone()
    }

    pub fn get_public_key(&self) -> String {
        hex::encode(self.public_key.serialize())
    }

    pub fn get_balance(&self) -> Amount {
        self.utxos.values().map(|utxo| utxo.value).sum()
    }

    pub fn add_utxo(&mut self, outpoint: OutPoint, txout: TxOut) {
        self.utxos.insert(outpoint, txout);
    }

    pub fn remove_utxo(&mut self, outpoint: &OutPoint) {
        self.utxos.remove(outpoint);
    }

    /// Calculate dust threshold for a given script
    fn get_dust_threshold(script_pubkey: &ScriptBuf) -> u64 {
        if script_pubkey.is_p2wpkh() {
            Self::P2WPKH_DUST_THRESHOLD
        } else if script_pubkey.is_p2tr() {
            Self::P2TR_DUST_THRESHOLD
        } else {
            Self::DEFAULT_DUST_THRESHOLD
        }
    }

    /// Check if an output value is dust
    fn is_dust(value: u64, script_pubkey: &ScriptBuf) -> bool {
        value < Self::get_dust_threshold(script_pubkey)
    }

    /// Calculate fee based on transaction size
    fn calculate_fee(inputs: usize, outputs: usize, fee_rate: u64) -> u64 {
        let base_size = 10;
        let input_size = inputs * 68;
        let output_size = outputs * 35;
        let total_vbytes = base_size + input_size + output_size;
        
        fee_rate * total_vbytes as u64
    }

    /// Create an HTLC initiation transaction
    pub fn create_htlc_initiation(
        &self,
        htlc: &BitcoinHTLC,
        amount: u64,
        input_utxos: Vec<(OutPoint, TxOut)>,
        fee_rate: u64,
    ) -> Result<Transaction> {
        let htlc_address = htlc.address()?;
        
        // Create inputs
        let mut inputs: Vec<TxIn> = Vec::new();
        let mut input_values: Vec<u64> = Vec::new();
        
        for (outpoint, txout) in input_utxos {
            inputs.push(TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            input_values.push(txout.value.to_sat());
        }

        // Calculate fee
        let estimated_fee = Self::calculate_fee(inputs.len(), 2, fee_rate);
        let total_input: u64 = input_values.iter().sum();

        // Validate we have enough funds
        if total_input < amount + estimated_fee {
            return Err(anyhow!(
                "Insufficient funds: need {} sats, have {} sats", 
                amount + estimated_fee, 
                total_input
            ));
        }

        // Create HTLC output
        let htlc_output = TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: htlc_address.script_pubkey(),
        };

        let mut outputs = vec![htlc_output];

        // Add change output if needed
        let change_amount = total_input - amount - estimated_fee;
        if change_amount > 0 {
            let change_script = self.address.script_pubkey();
            if !Self::is_dust(change_amount, &change_script) {
                outputs.push(TxOut {
                    value: Amount::from_sat(change_amount),
                    script_pubkey: change_script,
                });
            }
        }

        // Create unsigned transaction
        let mut unsigned_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        // Sign each input
        let mut sighash_cache = SighashCache::new(&mut unsigned_tx);

        for i in 0..input_values.len() {
            let pubkey_hash = hash160::Hash::hash(&self.public_key.serialize());
            let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey_hash.into());

            let sighash_type = EcdsaSighashType::All;
            let sighash = sighash_cache.p2wpkh_signature_hash(
                i,
                &script_pubkey,
                Amount::from_sat(input_values[i]),
                sighash_type,
            )?;

            let msg = Message::from(sighash);
            let signature = self.secp.sign_ecdsa(&msg, &self.private_key);

            let btc_signature = BitcoinSignature {
                signature,
                sighash_type,
            };
            
            let pubkey_bytes = self.public_key.serialize();
            *sighash_cache.witness_mut(i).unwrap() = Witness::p2wpkh(
                &btc_signature,
                &PublicKey::from_slice(&pubkey_bytes)?,
            )
        }

        Ok(sighash_cache.transaction().clone())
    }

    /// Create an HTLC redemption transaction
    pub fn create_htlc_redemption(
        &self,
        htlc: &BitcoinHTLC,
        secret: &str,
        recipient_address: &Address,
        input_utxo: (OutPoint, TxOut),
        fee_rate: u64,
    ) -> Result<Transaction> {
        let htlc_address = htlc.address()?;
        let (outpoint, txout) = input_utxo;
        
        // Calculate fee
        let estimated_fee = Self::calculate_fee(1, 1, fee_rate);
        let output_value = txout.value.to_sat().saturating_sub(estimated_fee);
        let recipient_script = recipient_address.script_pubkey();
        
        // Check if output would be dust
        if Self::is_dust(output_value, &recipient_script) {
            return Err(anyhow!(
                "Output value {} sats would be dust (threshold: {} sats). HTLC amount too small.",
                output_value,
                Self::get_dust_threshold(&recipient_script)
            ));
        }
        
        // Create transaction
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(4294967294),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: recipient_script,
            }],
        };
    
        // Get witness data from BitcoinHTLC
        let witness_data = htlc.redeem(secret)?;
        
        // Create prevouts for sighash calculation
        let prevouts = vec![TxOut {
            value: txout.value,
            script_pubkey: htlc_address.script_pubkey(),
        }];
        
        // Create sighash cache
        let mut sighash_cache = SighashCache::new(&tx);
        
        // Create the leaf hash from the redeem script
        let script_bytes = witness_data.script_bytes();
        let redeem_script = Script::from_bytes(&script_bytes);
        let leaf_hash = TapLeafHash::from_script(redeem_script, LeafVersion::TapScript);
    
        // Generate the sighash message
        let tap_sighash = sighash_cache.taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(prevouts.as_slice()),
            leaf_hash,
            TapSighashType::All,
        )?;
    
        let message = Message::from_digest_slice(tap_sighash.as_ref())?;
        let keypair = self.private_key.keypair(&self.secp);
        let signature = self.secp.sign_schnorr_no_aux_rand(&message, &keypair);
    
        // Serialize signature with sighash type
        let mut sig_serialized = signature.as_ref().to_vec();
        sig_serialized.push(TapSighashType::All as u8);
        
        // Construct the witness stack for redemption: [signature, secret, script, control_block]
        let mut witness = Witness::new();
        witness.push(&sig_serialized);
        witness.push(witness_data.secret().unwrap());
        witness.push(&witness_data.script_bytes());
        witness.push(witness_data.cb_bytes());
    
        tx.input[0].witness = witness;
        Ok(tx)
    }

    /// Create an HTLC refund transaction
    pub fn create_htlc_refund(
        &self,
        htlc: &BitcoinHTLC,
        refund_address: &Address,
        input_utxo: (OutPoint, TxOut),
        fee_rate: u64,
    ) -> Result<Transaction> {
        let htlc_address = htlc.address()?;
        let (outpoint, txout) = input_utxo;
        
        // Calculate fee
        let estimated_fee = Self::calculate_fee(1, 1, fee_rate);
        let output_value = txout.value.to_sat().saturating_sub(estimated_fee);
        let refund_script = refund_address.script_pubkey();
        
        // Check if output would be dust
        if Self::is_dust(output_value, &refund_script) {
            return Err(anyhow!(
                "Refund value {} sats would be dust (threshold: {} sats). HTLC amount too small.",
                output_value,
                Self::get_dust_threshold(&refund_script)
            ));
        }
        
        // Create transaction with timelock sequence
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(htlc.timelock() as u32),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: refund_script,
            }],
        };
    
        // Get witness data from BitcoinHTLC
        let witness_data = htlc.refund()?;
        
        // Create prevouts for sighash calculation
        let prevouts = vec![TxOut {
            value: txout.value,
            script_pubkey: htlc_address.script_pubkey(),
        }];
        
        // Create sighash cache
        let mut sighash_cache = SighashCache::new(&tx);
        
        // Create the leaf hash from the refund script
        let script_bytes = witness_data.script_bytes();
        let refund_script_bytes = Script::from_bytes(&script_bytes);
        let leaf_hash = TapLeafHash::from_script(refund_script_bytes, LeafVersion::TapScript);
    
        // Generate the sighash message
        let tap_sighash = sighash_cache.taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(prevouts.as_slice()),
            leaf_hash,
            TapSighashType::All,
        )?;
    
        let message = Message::from_digest_slice(tap_sighash.as_ref())?;
        let keypair = self.private_key.keypair(&self.secp);
        let signature = self.secp.sign_schnorr_no_aux_rand(&message, &keypair);
    
        // Serialize signature with sighash type
        let mut sig_serialized = signature.as_ref().to_vec();
        sig_serialized.push(TapSighashType::All as u8);
        
        // Construct the witness stack for refund: [signature, refund_script, control_block]
        let mut witness = Witness::new();
        witness.push(&sig_serialized);
        witness.push(&witness_data.script_bytes());
        witness.push(witness_data.cb_bytes());
    
        tx.input[0].witness = witness;
        Ok(tx)
    }

    /// Generate a random preimage for HTLC testing
    pub fn generate_preimage(&self) -> [u8; 32] {
        let mut preimage = [0u8; 32];
        for (i, byte) in preimage.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(0x42);
        }
        preimage
    }

    /// Hash a preimage to create a secret hash
    pub fn hash_preimage(preimage: &[u8; 32]) -> [u8; 32] {
        sha256::Hash::hash(preimage).to_byte_array()
    }

    /// Create a BitcoinHTLC instance with this wallet's public key as initiator
    pub fn create_htlc_as_initiator(
        &self,
        secret_hash: String,
        redeemer_pubkey: String,
        timelock: i64,
    ) -> Result<BitcoinHTLC> {
        BitcoinHTLC::new(
            secret_hash,
            self.get_public_key(),
            redeemer_pubkey,
            timelock,
            self.network,
        )
    }

    /// Create a BitcoinHTLC instance with this wallet's public key as redeemer
    pub fn create_htlc_as_redeemer(
        &self,
        secret_hash: String,
        initiator_pubkey: String,
        timelock: i64,
    ) -> Result<BitcoinHTLC> {
        BitcoinHTLC::new(
            secret_hash,
            initiator_pubkey,
            self.get_public_key(),
            timelock,
            self.network,
        )
    }
}