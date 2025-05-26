use bitcoin::{key::Secp256k1, Address, CompressedPublicKey, Network, PrivateKey, PublicKey};

use crate::indexer::indexer::IndexerClient;

use super::*;

pub struct SimpleWallet {
    private_key: PrivateKey,
    public_key: PublicKey,
    network: Network,
    indexer: IndexerClient,
}

impl SimpleWallet {
    pub fn new(priv_key_str: &str, network: &str, indexer_url: &str) -> Self {
        let secp = Secp256k1::new();
        let priv_key_bytes = hex::decode(priv_key_str).unwrap();
        let network = match network{
            "mainnet" => Network::Bitcoin,
            "testnet4" => Network::Testnet4,
            "regtest" => Network::Regtest,
            _ => panic!("Invalid network"),
        };
        let private_key = PrivateKey::from_slice(&priv_key_bytes, network).unwrap();
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        
        
        SimpleWallet {
            private_key,
            public_key,
            network,
            indexer: IndexerClient::new(indexer_url).unwrap(),
        }
    }
}

impl Wallet for SimpleWallet {
    fn address(&self) -> String {
        let public_key = CompressedPublicKey::try_from(self.public_key).unwrap();
        let address = Address::p2wpkh(&public_key, self.network);
        address.to_string()
    }
    
    async fn get_balance(&self) -> u64 {
        self.indexer.get_balance(&self.address()).await.unwrap_or(0)
    }

    fn build_transaction(&self, outputs: Vec<Output>) -> Result<Transaction, String> {
        todo!()
    }
    
    fn sign_and_send(&self, address: &str, amount: f64) -> Result<(), String> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_balance() {
        let wallet = SimpleWallet::new("BTC_PRIV_KEY", "testnet4", "https://mempool.space/testnet4/api");

        let runtime = tokio::runtime::Runtime::new()
            .expect("Unable to create runtime");

        let balance =
            runtime.block_on(wallet.get_balance());
        
        println!("wallet address:{:#?}", wallet.address());
        assert_eq!(balance, 0);
    }
}
