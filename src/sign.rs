use std::error::Error;

use bitcoin::{key::{Keypair, Secp256k1}, secp256k1::Message, sighash::SighashCache, Amount, EcdsaSighashType, PrivateKey, ScriptBuf, TapLeafHash, TapSighashType, Transaction, Witness};

pub fn sign_p2wpkh(unsigned_tx: Transaction, input_values: Vec<u64>, private_key: PrivateKey) -> Result<Transaction, Error>{
    let secp = Secp256k1::new();
    let public_key = private_key.public_key(&secp);
    
    let mut sighash_cache = SighashCache::new(&mut unsigned_tx);

    for i in 0..input_values.len() {
        let script_pubkey = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()?);

        let sighash_type = EcdsaSighashType::All;
        let sighash = sighash_cache.p2wpkh_signature_hash(
            i,
            &script_pubkey,
            Amount::from_sat(input_values[i]),
            sighash_type,
        )?;

        let msg = Message::from(sighash);
        let signature = secp.sign_ecdsa(&msg, &private_key.inner);


        let btc_signature = bitcoin::ecdsa::Signature {
            signature,
            sighash_type,
        };
        
        let pubkey_bytes = public_key.to_bytes();
        *sighash_cache.witness_mut(i).unwrap() = Witness::p2wpkh(
            &btc_signature,
            &bitcoin::secp256k1::PublicKey::from_slice(&pubkey_bytes)?,
        )
    }

    let signed_tx = sighash_cache.into_transaction();
    signed_tx
}

pub fn sign_p2tr(
    mut tx: Transaction,
    input_index: usize,
    leaf_hash: TapLeafHash,
    private_key: bitcoin::PrivateKey,
    sighash_type: TapSighashType,
    prevouts: Vec<bitcoin::TxOut>,
    witness_stack: Vec<Vec<u8>>
) -> Result<Transaction, Error> {
    
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &private_key.inner);

    // Create sighash cache for the transaction
    let mut sighash_cache = SighashCache::new(&tx);

    // Generate the sighash message to sign using taproot script spend path
    let tap_sighash = sighash_cache.taproot_script_spend_signature_hash(
        input_index,
        &bitcoin::sighash::Prevouts::All(prevouts.as_slice()),
        leaf_hash,
        sighash_type,
    )?;

    // Convert TapSighash to a Message
    let message = Message::from_digest_slice(tap_sighash.as_ref())?;

    // Sign the sighash with Schnorr signature
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);

    let mut sig_serialized = signature.as_ref().to_vec();
    if sighash_type != TapSighashType::Default {
        sig_serialized.push(sighash_type as u8);
    }

    // Create the witness
    let mut witness = Witness::new();

    // Add the signature as the first element
    witness.push(sig_serialized);
    witness.push(&witness_stack[1]);
    witness.push(&witness_stack[2]);
    witness.push(&witness_stack[3]);

    tx.input[input_index].witness = witness;

    Ok(tx)
}