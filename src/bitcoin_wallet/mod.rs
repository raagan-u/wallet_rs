use bitcoin::Transaction;

pub mod simple;
pub mod tx_builder;

pub trait Wallet {
    fn address(&self) -> String;
    async fn get_balance(&self) -> u64;
    async fn send(&self, address: &str, amount: f64) -> Result<(), String>;
}
