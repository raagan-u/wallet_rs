use bitcoin::{psbt::Output, Transaction};

pub mod simple;
pub mod htlc_wallet;
mod htlc;

pub trait Wallet {
    fn address(&self) -> String;
    async fn get_balance(&self) -> u64;
    fn build_transaction(&self, outputs: Vec<Output>) -> Result<Transaction, String>;
    fn sign_and_send(&self, address: &str, amount: f64) -> Result<(), String>;
}
