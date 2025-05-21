// Import types from crate root
use crate::types::{Block, Transaction, Hash};
use std::sync::RwLock;
use std::collections::HashMap;
use std::path::Path;
use log::{info, debug, error};
use rocksdb::{DB, Options};
use serde::{Serialize, Deserialize};
use chrono::Utc;
use sha2::{Sha256, Digest};

// Reduced rewards and constants
const GENESIS_BLOCK_REWARD: u64 = 5;  // Reduced from 50 to 5
const MINING_REWARD: u64 = 5;  // Reduced from 50 to 5
const MAX_TRANSACTIONS_PER_BLOCK: usize = 1000;
const UTXO_PREFIX: &[u8] = b"utxo-";
const BLOCK_PREFIX: &[u8] = b"block-";
const METADATA_KEY: &[u8] = b"metadata";

#[derive(Debug, Serialize, Deserialize)]
struct BlockchainMetadata {
    chain_height: u64,
    latest_block_hash: Hash,
    difficulty: u32, // Changed to u32 to match your Block header
}

pub struct Blockchain {
    chain: RwLock<Vec<Block>>,
    utxo_set: RwLock<HashMap<String, Vec<(Hash, u64)>>>,
    db: Option<DB>,
    data_dir: String,
}

impl Blockchain {
    pub fn new(data_dir: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let data_path = Path::new(data_dir);
        if !data_path.exists() {
            std::fs::create_dir_all(data_path)?;
        }

        let mut options = Options::default();
        options.create_if_missing(true);
        
        let db_path = data_path.join("blockchain.db");
        let db = match DB::open(&options, db_path) {
            Ok(db) => Some(db),
            Err(e) => {
                error!("Failed to open database: {}", e);
                None
            }
        };

        let blockchain = Blockchain {
            chain: RwLock::new(Vec::new()),
            utxo_set: RwLock::new(HashMap::new()),
            db,
            data_dir: data_dir.to_string(),
        };

        // Try to load chain from database, or create genesis block if it doesn't exist
        match blockchain.load_from_db() {
            Ok(loaded) => if !loaded {
                blockchain.create_genesis_block()?;
            },
            Err(e) => {
                error!("Failed to load blockchain from db: {}", e);
                blockchain.create_genesis_block()?;
            }
        }

        // Rebuild UTXO set from the chain (in a real implementation, we'd store this in the database)
        blockchain.rebuild_utxo_set()?;

        Ok(blockchain)
    }

    pub fn get_chain(&self) -> Vec<Block> {
        self.chain.read().unwrap().clone()
    }

    pub fn get_chain_height(&self) -> u64 {
        let chain = self.chain.read().unwrap();
        chain.len() as u64
    }

    pub fn get_latest_block(&self) -> Option<Block> {
        let chain = self.chain.read().unwrap();
        chain.last().cloned()
    }
    
    // Create a block template with mining reward to specific address
    pub fn create_block_template(&self, miner_address_str: &str) -> Block {
        // Convert miner address from hex string to bytes
        let mut miner_address = [0u8; 20];
        if let Ok(address_bytes) = hex::decode(miner_address_str) {
            if address_bytes.len() == 20 {
                miner_address.copy_from_slice(&address_bytes);
            }
        }
        
        // Create coinbase transaction with reward to miner
        let coinbase_tx = Transaction {
            from: [0u8; 20], // From the system (all zeros)
            to: miner_address,
            amount: MINING_REWARD, // Using reduced mining reward
            fee: 0,
            nonce: 0,
            signature: Vec::new(), // No signature needed for coinbase
        };
        
        let latest_block = self.get_latest_block();
        
        if let Some(latest) = latest_block {
            Block {
                header: crate::types::BlockHeader {
                    prev_hash: latest.hash(),
                    merkle_root: [0; 32], // Will be calculated later
                    timestamp: Utc::now().timestamp() as u64,
                    height: latest.header.height + 1,
                    nonce: 0,
                    difficulty: latest.header.difficulty, // Use the current difficulty
                },
                transactions: vec![coinbase_tx], // Start with just the coinbase
                zk_proof: Some(Vec::new()),
            }
        } else {
            // Genesis block case (should not happen here, but just in case)
            Block {
                header: crate::types::BlockHeader {
                    prev_hash: [0; 32],
                    merkle_root: [0; 32],
                    timestamp: Utc::now().timestamp() as u64,
                    height: 0,
                    nonce: 0,
                    difficulty: 20, // Higher initial difficulty
                },
                transactions: vec![coinbase_tx],
                zk_proof: Some(Vec::new()),
            }
        }
    }
    
    fn create_genesis_block(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create a simple genesis block with a reward to a placeholder address
        let timestamp = Utc::now().timestamp() as u64;
        
        // Create a miner reward transaction
        let miner_address = [0u8; 20]; // Genesis block reward goes to address 0
        let genesis_transaction = Transaction {
            from: [0u8; 20], // From the system (all zeros)
            to: miner_address,
            amount: GENESIS_BLOCK_REWARD, // Reduced reward
            fee: 0,
            nonce: 0,
            signature: Vec::new(), // No signature needed for coinbase
        };

        // Use the correct structure for your BlockHeader
        let mut genesis_block = Block {
            header: crate::types::BlockHeader {
                prev_hash: [0; 32], // All zeros for genesis block
                merkle_root: [0; 32], // Will be calculated
                timestamp,
                height: 0,
                nonce: 0,
                difficulty: 20, // Higher initial difficulty
            },
            transactions: vec![genesis_transaction],
            zk_proof: Some(Vec::new()), // Using Option<Vec<u8>> based on the error message
        };

        // Calculate the merkle root hash
        genesis_block.header.merkle_root = self.calculate_merkle_root(&genesis_block.transactions);
        
        // Add the block to our chain
        {
            let mut chain = self.chain.write().unwrap();
            chain.push(genesis_block.clone());
        }

        // Save to database
        if let Some(db) = &self.db {
            let block_key = [BLOCK_PREFIX, &0u64.to_be_bytes()].concat();
            let block_data = serde_json::to_vec(&genesis_block)?;
            db.put(block_key, block_data)?;
            
            // Save metadata
            let metadata = BlockchainMetadata {
                chain_height: 0,
                latest_block_hash: genesis_block.hash(),
                difficulty: 20, // Higher initial difficulty
            };
            let metadata_data = serde_json::to_vec(&metadata)?;
            db.put(METADATA_KEY, metadata_data)?;
        }

        info!("Created genesis block");
        Ok(())
    }

    pub fn add_block(&mut self, mut block: Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Ensure the block is valid
        self.validate_block(&block)?;
        
        // Calculate the merkle root
        block.header.merkle_root = self.calculate_merkle_root(&block.transactions);
        
        // Adjust difficulty every 10 blocks
        if block.header.height % 10 == 0 && block.header.height > 0 {
            let chain = self.chain.read().unwrap();
            if chain.len() >= 10 {
                // Get the timestamps of the last 10 blocks
                let start_time = chain[chain.len() - 10].header.timestamp;
                let end_time = block.header.timestamp;
                
                // Target time for 10 blocks (10 minutes per block)
                let target_time_seconds = 10 * 10 * 60; // 10 blocks * 10 minutes * 60 seconds
                let actual_time_seconds = end_time.saturating_sub(start_time) as i64;
                
                // Adjust difficulty based on how quickly blocks were mined
                if actual_time_seconds < target_time_seconds / 2 {
                    // Too fast - increase difficulty
                    block.header.difficulty = block.header.difficulty.saturating_add(1);
                    info!("Mining difficulty increased to {}", block.header.difficulty);
                } else if actual_time_seconds > target_time_seconds * 2 {
                    // Too slow - decrease difficulty (but never below initial difficulty)
                    block.header.difficulty = block.header.difficulty.saturating_sub(1).max(20);
                    info!("Mining difficulty decreased to {}", block.header.difficulty);
                }
            }
        }
        
        // Add the block to our chain
        {
            let mut chain = self.chain.write().unwrap();
            chain.push(block.clone());
        }

        // Update UTXO set
        self.update_utxo_set(&block)?;

        // Save to database
        if let Some(db) = &self.db {
            let block_key = [BLOCK_PREFIX, &block.header.height.to_be_bytes()].concat();
            let block_data = serde_json::to_vec(&block)?;
            db.put(block_key, block_data)?;
            
            // Update metadata
            let metadata = BlockchainMetadata {
                chain_height: block.header.height,
                latest_block_hash: block.hash(),
                difficulty: block.header.difficulty,
            };
            let metadata_data = serde_json::to_vec(&metadata)?;
            db.put(METADATA_KEY, metadata_data)?;
        }

        info!("Added new block at height {}", block.header.height);
        Ok(())
    }

    fn validate_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get the latest block
        let latest_block = self.get_latest_block()
            .ok_or("Cannot validate block: chain is empty")?;

        // Check block height
        if block.header.height != latest_block.header.height + 1 {
            return Err(format!("Invalid block height: expected {}, got {}", 
                             latest_block.header.height + 1, block.header.height).into());
        }

        // Check prev_hash
        if block.header.prev_hash != latest_block.hash() {
            return Err("Invalid previous hash".into());
        }

        // Check timestamp (must be after previous block)
        if block.header.timestamp <= latest_block.header.timestamp {
            return Err("Block timestamp is invalid".into());
        }

        // Check transactions (not too many)
        if block.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
            return Err(format!("Too many transactions: {} (max: {})", 
                             block.transactions.len(), MAX_TRANSACTIONS_PER_BLOCK).into());
        }

        // Check that the block meets the difficulty requirement
        if !block.is_valid_proof_of_work() {
            return Err("Block does not meet proof-of-work requirement".into());
        }

        // Validate each transaction
        let is_mining_block = block.transactions.len() > 0 && 
                            block.transactions[0].from == [0u8; 20];
        
        if !is_mining_block {
            for tx in &block.transactions {
                self.validate_transaction(tx)?;
            }
        } else {
            // For mining blocks, validate all transactions except the first (coinbase)
            for tx in block.transactions.iter().skip(1) {
                self.validate_transaction(tx)?;
            }
            
            // Check that coinbase reward is correct
            if block.transactions[0].amount > MINING_REWARD {
                return Err(format!("Invalid mining reward: got {}, expected {}", 
                                 block.transactions[0].amount, MINING_REWARD).into());
            }
        }

        Ok(())
    }

fn validate_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Skip validation for mining rewards
    if tx.from == [0u8; 20] {
        return Ok(());
    }

    // Verify transaction signature
    if !tx.verify() {
        return Err("Invalid transaction signature".into());
    }

    // Check that sender has enough funds
    let sender_address = hex::encode(tx.from);
    let required_amount = tx.amount + tx.fee;
    
    let utxo_set = self.utxo_set.read().unwrap();
    let sender_utxos = utxo_set.get(&sender_address);
    
    if sender_utxos.is_none() {
        return Err(format!("Sender {} has no UTXOs", sender_address).into());
    }
    
    let sender_balance: u64 = sender_utxos.unwrap().iter()
        .map(|(_, amount)| amount)
        .sum();
    
    if sender_balance < required_amount {
        return Err(format!("Insufficient funds: {} < {}", sender_balance, required_amount).into());
    }

    Ok(())
}
    fn verify_signature(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Simplified signature verification
        // In a real implementation, we'd use the UTXO model properly
        // and verify against the public key

        // Skip coinbase transactions
        if tx.from == [0u8; 20] || tx.signature.is_empty() {
            return Ok(());
        }

        // For now, assume all signatures are valid
        // In a real implementation, we'd do:
        // let tx_hash = tx.hash();
        // let msg = secp256k1::Message::from_slice(&tx_hash)?;
        // let sig = secp256k1::ecdsa::Signature::from_compact(&tx.signature)?;
        // let pubkey = PublicKey::from_slice(&tx.sender_pubkey)?;
        // secp256k1::verify(&msg, &sig, &pubkey)?;

        Ok(())
    }

    fn update_utxo_set(&self, block: &Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut utxo_set = self.utxo_set.write().unwrap();
        
        for tx in &block.transactions {
            // Skip coinbase transactions for input processing
            if tx.from != [0u8; 20] {
                let sender = hex::encode(tx.from);
                
                // Remove used inputs
                let spent_amount = tx.amount + tx.fee;
                let mut remaining = spent_amount;
                
                if let Some(sender_utxos) = utxo_set.get_mut(&sender) {
                    let mut i = 0;
                    while i < sender_utxos.len() && remaining > 0 {
                        let (_, amount) = sender_utxos[i];
                        
                        if amount <= remaining {
                            // Use the entire UTXO
                            remaining -= amount;
                            sender_utxos.remove(i);
                        } else {
                            // Use part of the UTXO
                            sender_utxos[i].1 -= remaining;
                            remaining = 0;
                            i += 1;
                        }
                    }
                    
                    // If we couldn't spend enough, this is an error
                    if remaining > 0 {
                        return Err("Insufficient funds in UTXO set".into());
                    }
                    
                    // Create change UTXO if needed
                    if spent_amount < tx.amount + tx.fee {
                        let change = (tx.amount + tx.fee) - spent_amount;
                        sender_utxos.push((tx.hash(), change));
                    }
                    
                    // Clean up if empty
                    if sender_utxos.is_empty() {
                        utxo_set.remove(&sender);
                    }
                }
            }
            
            // Add new output to recipient
            let recipient = hex::encode(tx.to);
            let entry = utxo_set.entry(recipient.clone()).or_insert_with(Vec::new);
            entry.push((tx.hash(), tx.amount));
            
            // Log for mining rewards
            if tx.from == [0u8; 20] {
                info!("Mining reward of {} PALI added to {}", tx.amount, recipient);
            }
        }
        
        Ok(())
    }

    fn rebuild_utxo_set(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut utxo_set = self.utxo_set.write().unwrap();
        utxo_set.clear();
        
        let chain = self.chain.read().unwrap();
        
        for block in chain.iter() {
            for tx in &block.transactions {
                // Process inputs (skip coinbase)
                if tx.from != [0u8; 20] {
                    let sender = hex::encode(tx.from);
                    let spent_amount = tx.amount + tx.fee;
                    
                    if let Some(sender_utxos) = utxo_set.get_mut(&sender) {
                        let mut remaining = spent_amount;
                        let mut i = 0;
                        
                        while i < sender_utxos.len() && remaining > 0 {
                            let (_, amount) = sender_utxos[i];
                            
                            if amount <= remaining {
                                // Use the entire UTXO
                                remaining -= amount;
                                sender_utxos.remove(i);
                            } else {
                                // Use part of the UTXO
                                sender_utxos[i].1 -= remaining;
                                remaining = 0;
                                i += 1;
                            }
                        }
                        
                        if sender_utxos.is_empty() {
                            utxo_set.remove(&sender);
                        }
                    }
                }
                
                // Add output
                let recipient = hex::encode(tx.to);
                let entry = utxo_set.entry(recipient.clone()).or_insert_with(Vec::new);
                entry.push((tx.hash(), tx.amount));
                
                // Log for mining rewards during rebuild
                if tx.from == [0u8; 20] {
                    info!("Loaded mining reward of {} PALI for {}", tx.amount, recipient);
                }
            }
        }
        
        debug!("Rebuilt UTXO set with {} addresses", utxo_set.len());
        Ok(())
    }

    fn load_from_db(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(db) = &self.db {
            // Try to load metadata
            if let Ok(Some(metadata_bytes)) = db.get(METADATA_KEY) {
                let metadata: BlockchainMetadata = serde_json::from_slice(&metadata_bytes)?;
                
                let mut chain = self.chain.write().unwrap();
                chain.clear();
                
                // Load all blocks
                for height in 0..=metadata.chain_height {
                    let block_key = [BLOCK_PREFIX, &height.to_be_bytes()].concat();
                    
                    if let Ok(Some(block_bytes)) = db.get(block_key) {
                        let block: Block = serde_json::from_slice(&block_bytes)?;
                        chain.push(block);
                    } else {
                        return Err(format!("Failed to load block at height {}", height).into());
                    }
                }
                
                info!("Loaded {} blocks from database", chain.len());
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    pub fn get_balance(&self, address: &str) -> u64 {
        let utxo_set = self.utxo_set.read().unwrap();
        
        let balance = utxo_set.get(address)
            .map(|utxos| utxos.iter().map(|(_, amount)| *amount).sum())
            .unwrap_or(0);
            
        debug!("Balance for {}: {} PALI", address, balance);
        balance
    }

    fn calculate_merkle_root(&self, transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return [0; 32];
        }
        
        let mut hashes: Vec<Hash> = transactions.iter()
            .map(|tx| tx.hash())
            .collect();
        
        while hashes.len() > 1 {
            let mut new_hashes = Vec::new();
            
            // Group hashes in pairs
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                
                // Hash the pair (or single if odd number)
                if chunk.len() == 2 {
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[0]); // Duplicate if odd
                }
                
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                
                new_hashes.push(hash);
            }
            
            hashes = new_hashes;
        }
        
        hashes[0]
    }
}
