use std::time::Duration;

use bitcoin::Transaction;
use thiserror::Error;

use crate::types::UTXO;

pub struct IndexerClient {
    url : String,
    client: reqwest::Client
}

#[derive(Error, Debug)]
pub enum IndexerError {
    #[error("HTTP request failed: {0}")]
        RequestError(#[from] reqwest::Error),
        
    #[error("Error parsing response: {0}")]
    ParseError(String),
    #[error("Error fetching utxos: {0}")]
    UtxoError(String)
}

impl IndexerClient {
    pub async fn new(url: String) -> Result<Self, IndexerError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| IndexerError::RequestError(e))?;
        
        Ok(Self { url, client })
    }
    
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<UTXO>, IndexerError> {
        let url = format!("{}/address/{}/utxo", self.url, address);
        let resp = self.client.get(url).send().await?;
        let text = resp.text().await?;
        serde_json::from_str::<Vec<UTXO>>(&text)
                .map_err(|e| IndexerError::ParseError(format!("Failed to parse: {}, response: {}", e, text)))
    }
    
    pub async fn get_utxos_for_amount(&self, address: &str, amount: i64) -> Result<Vec<UTXO>, IndexerError> {
        let unfiltered_utxos = self.get_utxos(&address).await?;
        let mut filtered_utxos: Vec<UTXO> = Vec::new();
        let mut total = 0;

        for utxo in unfiltered_utxos {
            total += utxo.value as i64;
            filtered_utxos.push(utxo);
            if total == amount {
                return Ok(filtered_utxos);
            }
        }

        if total < amount {
            return Err(IndexerError::UtxoError(format!("insufficent balance expected {} got {} ", amount, total)));
        }
        Ok(filtered_utxos)
    }
    
    pub async fn get_tx(&self, txid: &str) -> Result<Transaction, IndexerError> {
        let url = format!("{}/tx/{}", self.url, txid);
        let resp = self.client.get(url).send().await?;
        let txhex = resp.text().await?;
        let txhex_bytes = hex::decode(&txhex).map_err(|e| IndexerError::ParseError(format!("error decoding hex bytes {}", e)))?;
        
        let tx = bitcoin::consensus::deserialize(&txhex_bytes).unwrap();
        
        Ok(tx)
    }
}