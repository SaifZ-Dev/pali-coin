use pali_coin::blockchain::Blockchain;
use pali_coin::types::Block;
use std::sync::{Arc, Mutex};

pub struct NodeService {
    blockchain: Arc<Mutex<Blockchain>>,
}

impl NodeService {
    pub fn new(data_dir: &str, chain_id: u64) -> Self {
        let blockchain = Blockchain::new(data_dir, chain_id);
        NodeService {
            blockchain: Arc::new(Mutex::new(blockchain)),
        }
    }

    pub fn get_chain_height(&self) -> u64 {
        self.blockchain.lock().unwrap().height
    }

    pub fn get_latest_block(&self) -> Block {
        let blockchain = self.blockchain.lock().unwrap();
        blockchain.get_block(&blockchain.best_hash).unwrap().clone()
    }

    pub fn create_block_template(&self, miner_address: &str) -> Block {
        let mut blockchain = self.blockchain.lock().unwrap();
        
        // Convert string address to bytes
        let address_bytes = hex::decode(miner_address).unwrap();
        let mut address = [0u8; 20];
        address.copy_from_slice(&address_bytes);
        
        blockchain.create_block_template(&address)
    }

    pub fn get_balance(&self, address_str: &str) -> u64 {
        let blockchain = self.blockchain.lock().unwrap();
        
        // Convert string address to bytes
        let address_bytes = hex::decode(address_str).unwrap();
        let mut address = [0u8; 20];
        address.copy_from_slice(&address_bytes);
        
        blockchain.get_balance(&address)
    }

    pub fn get_chain(&self) -> Vec<Block> {
        let blockchain = self.blockchain.lock().unwrap();
        blockchain.get_chain()
    }
}

fn main() {
    println!("Pali Coin Node");
    let node = NodeService::new("data", 1);
    println!("Chain height: {}", node.get_chain_height());
}
