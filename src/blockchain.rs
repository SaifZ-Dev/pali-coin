// Import types from crate root
use crate::types::{Block, Transaction, Hash};
use std::sync::RwLock;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use log::{info, debug, error, warn};
use rocksdb::{DB, Options};
use serde::{Serialize, Deserialize};
use chrono::Utc;
use sha2::{Sha256, Digest};
use rand::{thread_rng, Rng};

// Economic constants
const GENESIS_BLOCK_REWARD: u64 = 5;  // Initial reward
const BASE_MINING_REWARD: u64 = 5;    // Base mining reward
const MAX_TRANSACTIONS_PER_BLOCK: usize = 1000;
const UTXO_PREFIX: &[u8] = b"utxo-";
const BLOCK_PREFIX: &[u8] = b"block-";
const METADATA_KEY: &[u8] = b"metadata";
const ECONOMY_KEY: &[u8] = b"economy";
const REWARD_HALVING_PERIOD: u64 = 210000;  // Halve rewards every 210,000 blocks (like Bitcoin)
const DIFFICULTY_ADJUSTMENT_PERIOD: u64 = 10; // Adjust difficulty every 10 blocks
const TARGET_BLOCK_TIME_SECONDS: u64 = 600; // Target 10 minutes per block
const TRANSACTION_HISTORY_SIZE: usize = 100; // Number of blocks to consider for transaction volume

#[derive(Debug, Serialize, Deserialize)]
struct BlockchainMetadata {
    chain_height: u64,
    latest_block_hash: Hash,
    difficulty: u32,
    current_base_reward: u64,       // Current base reward after halvings
    last_halving_height: u64,       // Height of last halving event
    economic_adjustment_factor: u64, // Current economic adjustment percentage (100 = normal)
}

#[derive(Debug, Serialize, Deserialize)]
struct EconomyData {
    transaction_volumes: Vec<u64>,   // Recent transaction volumes
    transaction_counts: Vec<usize>,  // Recent transaction counts
    mining_distribution: HashMap<String, u64>, // Mining rewards by address
    average_fees: f64,               // Rolling average transaction fee
}

pub struct Blockchain {
    chain: RwLock<Vec<Block>>,
    utxo_set: RwLock<HashMap<String, Vec<(Hash, u64)>>>,
    db: Option<DB>,
    data_dir: String,
    
    // Economic tracking
    current_reward: RwLock<u64>,             // Current mining reward after halvings and adjustments
    last_halving_height: RwLock<u64>,        // Block height of last halving
    last_block_times: RwLock<VecDeque<u64>>, // Recent block timestamps for difficulty adjustment
    transaction_history: RwLock<VecDeque<(usize, u64)>>, // Recent (tx_count, volume) pairs
    economic_adjustment: RwLock<u64>,        // Economic adjustment factor (percentage: 100 = normal)
    active_miners: RwLock<HashMap<String, u64>>, // Track miners and reward distribution
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
            
            // Initialize economic tracking
            current_reward: RwLock::new(BASE_MINING_REWARD),
            last_halving_height: RwLock::new(0),
            last_block_times: RwLock::new(VecDeque::with_capacity(10)),
            transaction_history: RwLock::new(VecDeque::with_capacity(TRANSACTION_HISTORY_SIZE)),
            economic_adjustment: RwLock::new(100), // 100% = no adjustment
            active_miners: RwLock::new(HashMap::new()),
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

        // Rebuild UTXO set from the chain
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
    
    // Calculate the current mining reward based on blockchain state and network activity
    fn calculate_mining_reward(&self, miner_address_str: &str) -> u64 {
        // Get base values from locks
        let base_reward = *self.current_reward.read().unwrap();
        let chain_height = self.get_chain_height();
        let last_halving_height = *self.last_halving_height.read().unwrap();
        
        // Check if we need to halve the reward
        if chain_height >= last_halving_height + REWARD_HALVING_PERIOD {
            // Time for halving
            let mut reward = self.current_reward.write().unwrap();
            *reward = (*reward).saturating_div(2).max(1); // Minimum reward of 1
            
            // Update last halving height
            let mut halving_height = self.last_halving_height.write().unwrap();
            *halving_height = chain_height;
            
            info!("Mining reward halved to {} at height {}", *reward, chain_height);
        }
        
        // Apply economic adjustment factor
        let adjustment_factor = *self.economic_adjustment.read().unwrap();
        let mut adjusted_reward = base_reward * adjustment_factor / 100;
        
        // Add transaction fee incentive during low network activity
        let tx_history = self.transaction_history.read().unwrap();
        if !tx_history.is_empty() {
            // Calculate average transactions per block
            let avg_tx_count: f64 = tx_history.iter().map(|(count, _)| *count as f64).sum::<f64>() / tx_history.len() as f64;
            
            // If transaction count is low, provide bonus to incentivize mining
            if avg_tx_count < 5.0 {
                let bonus = (base_reward / 10).max(1); // 10% bonus, minimum 1
                adjusted_reward = adjusted_reward.saturating_add(bonus);
                debug!("Adding low activity bonus of {} to mining reward", bonus);
            }
        }
        
        // Apply miner distribution factor - give slight bonus to new miners
        let mut active_miners = self.active_miners.write().unwrap();
        let miner_blocks = active_miners.entry(miner_address_str.to_string()).or_insert(0);
        *miner_blocks += 1;
        
        // Bonus for miners with fewer blocks (encourage decentralization)
        if *miner_blocks <= 10 {
            let decentralization_bonus = base_reward / 20; // 5% bonus
            adjusted_reward = adjusted_reward.saturating_add(decentralization_bonus);
            debug!("Adding decentralization bonus of {} for newer miner", decentralization_bonus);
        }
        
        // Apply randomness factor (±2%) to create minor variations in rewards
        let mut rng = thread_rng();
        let random_factor = rng.gen_range(98..=102);
        let final_reward = (adjusted_reward * random_factor / 100).max(1); // Minimum reward of 1
        
        debug!("Calculated mining reward: {} PALI for miner {}", final_reward, miner_address_str);
        final_reward
    }
    
    // Update economic factors based on network activity
    fn update_economic_factors(&self, block: &Block) {
        // Record transaction data
        let tx_count = block.transactions.len().saturating_sub(1); // Exclude coinbase
        let tx_volume: u64 = block.transactions.iter()
            .skip(1) // Skip coinbase
            .map(|tx| tx.amount)
            .sum();
        
        // Update transaction history
        let mut tx_history = self.transaction_history.write().unwrap();
        tx_history.push_back((tx_count, tx_volume));
        if tx_history.len() > TRANSACTION_HISTORY_SIZE {
            tx_history.pop_front();
        }
        
        // Update block timestamps for difficulty adjustment
        let mut block_times = self.last_block_times.write().unwrap();
        block_times.push_back(block.header.timestamp);
        if block_times.len() > 10 {
            block_times.pop_front();
        }
        
        // Calculate economic health indicators after accumulating enough data
        if tx_history.len() >= 10 {
            // Calculate transaction growth or decline
            let recent_count: usize = tx_history.iter().rev().take(5).map(|(count, _)| *count).sum();
            let older_count: usize = tx_history.iter().rev().skip(5).take(5).map(|(count, _)| *count).sum();
            
            let tx_growth_factor = if older_count == 0 {
                100 // Default value if no older transactions
            } else {
                (recent_count * 100) / older_count.max(1)
            };
            
            // Update economic adjustment factor
            let mut adjustment = self.economic_adjustment.write().unwrap();
            if tx_growth_factor > 120 { // Strong growth (>20%)
                // Economy booming - slightly decrease rewards to control inflation
                *adjustment = adjustment.saturating_mul(98).saturating_div(100).max(80);
                info!("Economic adjustment: Reducing rewards to {}% due to strong network growth", *adjustment);
            } else if tx_growth_factor < 80 { // Strong decline (>20%)
                // Economy struggling - boost rewards to stimulate activity
                *adjustment = adjustment.saturating_mul(102).saturating_div(100).min(120);
                info!("Economic adjustment: Increasing rewards to {}% to stimulate network activity", *adjustment);
            } else {
                // Stable economy - gradually return to baseline
                if *adjustment > 100 {
                    *adjustment = adjustment.saturating_sub(1);
                } else if *adjustment < 100 {
                    *adjustment = adjustment.saturating_add(1);
                }
            }
        }
    }
    
    // Create a block template with dynamic mining reward to specific address
    pub fn create_block_template(&self, miner_address_str: &str) -> Block {
        // Convert miner address from hex string to bytes
        let mut miner_address = [0u8; 20];
        if let Ok(address_bytes) = hex::decode(miner_address_str) {
            if address_bytes.len() == 20 {
                miner_address.copy_from_slice(&address_bytes);
            }
        }
        
        // Calculate dynamic mining reward for this block
        let mining_reward = self.calculate_mining_reward(miner_address_str);
        
        // Create coinbase transaction with dynamic reward to miner
        let coinbase_tx = Transaction {
            from: [0u8; 20], // From the system (all zeros)
            to: miner_address,
            amount: mining_reward,
            fee: 0,
            nonce: 0,
            signature: Vec::new(), // No signature needed for coinbase
        };
        
        let latest_block = self.get_latest_block();
        
        if let Some(latest) = latest_block {
            // Generate a random starting nonce to ensure mining uniqueness
            let mut rng = thread_rng();
            let random_nonce = rng.gen::<u64>();
            
            Block {
                header: crate::types::BlockHeader {
                    prev_hash: latest.hash(),
                    merkle_root: [0; 32], // Will be calculated later
                    timestamp: Utc::now().timestamp() as u64,
                    height: latest.header.height + 1,
                    nonce: random_nonce, // Use random nonce as starting point
                    difficulty: latest.header.difficulty,
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
            amount: GENESIS_BLOCK_REWARD,
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
            zk_proof: Some(Vec::new()),
        };

        // Calculate the merkle root hash
        genesis_block.header.merkle_root = self.calculate_merkle_root(&genesis_block.transactions);
        
        // Add the block to our chain
        {
            let mut chain = self.chain.write().unwrap();
            chain.push(genesis_block.clone());
        }
        
        // Initialize economic tracking
        {
            let mut last_block_times = self.last_block_times.write().unwrap();
            last_block_times.push_back(timestamp);
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
                current_base_reward: BASE_MINING_REWARD,
                last_halving_height: 0,
                economic_adjustment_factor: 100,
            };
            let metadata_data = serde_json::to_vec(&metadata)?;
            db.put(METADATA_KEY, metadata_data)?;
            
            // Initialize economy data
            let economy_data = EconomyData {
                transaction_volumes: Vec::new(),
                transaction_counts: Vec::new(),
                mining_distribution: HashMap::new(),
                average_fees: 0.0,
            };
            let economy_data_bytes = serde_json::to_vec(&economy_data)?;
            db.put(ECONOMY_KEY, economy_data_bytes)?;
        }

        info!("Created genesis block");
        Ok(())
    }

    pub fn add_block(&mut self, mut block: Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Ensure the block is valid
        self.validate_block(&block)?;
        
        // Calculate the merkle root
        block.header.merkle_root = self.calculate_merkle_root(&block.transactions);
        
        // Adjust difficulty based on network conditions
        if block.header.height % DIFFICULTY_ADJUSTMENT_PERIOD == 0 && block.header.height > 0 {
            let block_times = self.last_block_times.read().unwrap();
            if block_times.len() >= 2 {
                // Calculate average time between blocks
                let time_diffs: Vec<u64> = block_times.iter().zip(block_times.iter().skip(1))
                    .map(|(a, b)| b.saturating_sub(*a))
                    .collect();
                
                let avg_time = if !time_diffs.is_empty() {
                    time_diffs.iter().sum::<u64>() / time_diffs.len() as u64
                } else {
                    TARGET_BLOCK_TIME_SECONDS
                };
                
                // Target time for blocks
                let target_time = TARGET_BLOCK_TIME_SECONDS;
                
                // Adjust difficulty based on how quickly blocks were mined
                if avg_time < target_time / 2 {
                    // Too fast - increase difficulty
                    block.header.difficulty = block.header.difficulty.saturating_add(1);
                    info!("Mining difficulty increased to {} (blocks too fast: {}s vs target {}s)", 
                         block.header.difficulty, avg_time, target_time);
                } else if avg_time > target_time * 2 {
                    // Too slow - decrease difficulty (but never below initial difficulty)
                    block.header.difficulty = block.header.difficulty.saturating_sub(1).max(20);
                    info!("Mining difficulty decreased to {} (blocks too slow: {}s vs target {}s)",
                         block.header.difficulty, avg_time, target_time);
                } else {
                    debug!("Mining difficulty stable at {} (avg time: {}s, target: {}s)",
                          block.header.difficulty, avg_time, target_time);
                }
            }
        }
        
        // Update economic factors based on this block
        self.update_economic_factors(&block);
        
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
                current_base_reward: *self.current_reward.read().unwrap(),
                last_halving_height: *self.last_halving_height.read().unwrap(),
                economic_adjustment_factor: *self.economic_adjustment.read().unwrap(),
            };
            let metadata_data = serde_json::to_vec(&metadata)?;
            db.put(METADATA_KEY, metadata_data)?;
            
            // Save economic data
            let tx_history = self.transaction_history.read().unwrap();
            let tx_volumes: Vec<u64> = tx_history.iter().map(|(_, volume)| *volume).collect();
            let tx_counts: Vec<usize> = tx_history.iter().map(|(count, _)| *count).collect();
            
            // Calculate average fee if there are transactions
            let avg_fee = if !tx_history.is_empty() {
                let total_txs: usize = tx_counts.iter().sum();
                if total_txs > 0 {
                    let chain = self.chain.read().unwrap();
                    let total_fees: f64 = chain.iter().flat_map(|b| b.transactions.iter().skip(1))
                        .map(|tx| tx.fee as f64)
                        .sum();
                    total_fees / total_txs as f64
                } else {
                    0.0
                }
            } else {
                0.0
            };
            
            let economy_data = EconomyData {
                transaction_volumes: tx_volumes,
                transaction_counts: tx_counts,
                mining_distribution: self.active_miners.read().unwrap().clone(),
                average_fees: avg_fee,
            };
            
            let economy_data_bytes = serde_json::to_vec(&economy_data)?;
            db.put(ECONOMY_KEY, economy_data_bytes)?;
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
            
            // Calculate expected reward for this miner
            let miner_addr_str = hex::encode(block.transactions[0].to);
            let expected_max_reward = self.calculate_mining_reward(&miner_addr_str);
            
            // Allow a small margin for timestamp differences
            let margin = expected_max_reward / 50; // 2% margin
            let max_allowed = expected_max_reward + margin;
            
            // Check that coinbase reward is not excessive
            if block.transactions[0].amount > max_allowed {
                return Err(format!("Excessive mining reward: got {}, max expected {}", 
                                 block.transactions[0].amount, max_allowed).into());
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
                } else {
                    // For coinbase transactions, record miner activity
                    let miner_addr = hex::encode(tx.to);
                    let mut miners = self.active_miners.write().unwrap();
                    let count = miners.entry(miner_addr.clone()).or_insert(0);
                    *count += 1;
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
                
                // Update economic parameters from stored metadata
                {
                    let mut current_reward = self.current_reward.write().unwrap();
                    *current_reward = metadata.current_base_reward;
                    
                    let mut last_halving = self.last_halving_height.write().unwrap();
                    *last_halving = metadata.last_halving_height;
                    
                    let mut economic_adj = self.economic_adjustment.write().unwrap();
                    *economic_adj = metadata.economic_adjustment_factor;
                }
                
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
                
                // Load economic data if available
                if let Ok(Some(economy_bytes)) = db.get(ECONOMY_KEY) {
                    let economy: EconomyData = serde_json::from_slice(&economy_bytes)?;
                    
                    // Reconstruct transaction history
                    let mut tx_history = self.transaction_history.write().unwrap();
                    tx_history.clear();
                    
                    for i in 0..economy.transaction_counts.len() {
                        if i < economy.transaction_volumes.len() {
                            tx_history.push_back((economy.transaction_counts[i], economy.transaction_volumes[i]));
                        }
                    }
                    
                    // Load miner distribution
                    let mut miners = self.active_miners.write().unwrap();
                    *miners = economy.mining_distribution;
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
    
    // Get blockchain economic statistics
    pub fn get_economic_stats(&self) -> serde_json::Value {
        let chain_height = self.get_chain_height();
        let current_reward = *self.current_reward.read().unwrap();
        let economic_adjustment = *self.economic_adjustment.read().unwrap();
        let miners = self.active_miners.read().unwrap();
        let tx_history = self.transaction_history.read().unwrap();
        
        // Calculate average transaction count and volume
        let (avg_tx_count, avg_tx_volume) = if !tx_history.is_empty() {
            let count_sum: usize = tx_history.iter().map(|(count, _)| *count).sum();
            let volume_sum: u64 = tx_history.iter().map(|(_, volume)| *volume).sum();
            
            (
                count_sum as f64 / tx_history.len() as f64,
                volume_sum as f64 / tx_history.len() as f64
            )
        } else {
            (0.0, 0.0)
        };
        
        // Count unique miners
        let active_miners = miners.len();
        
        // Identify most active miner
        let most_active_miner = if !miners.is_empty() {
            miners.iter()
                .max_by_key(|(_, count)| *count)
                .map(|(addr, count)| (addr.clone(), *count))
        } else {
            None
        };
        
        // Calculate mining centralization index (0-100, lower is more decentralized)
        let mining_centralization_index = if !miners.is_empty() {
            let total_blocks: u64 = miners.values().sum();
            let max_miner_percentage = if total_blocks > 0 {
                (most_active_miner.as_ref().map(|(_, count)| *count).unwrap_or(0) * 100) / total_blocks
            } else {
                0
            };
            max_miner_percentage
        } else {
            0
        };
        
        // Calculate next halving block
        let next_halving_height = self.last_halving_height.read().unwrap() + REWARD_HALVING_PERIOD;
        let blocks_until_halving = if chain_height < next_halving_height {
            next_halving_height - chain_height
        } else {
            0
        };
        
        serde_json::json!({
            "chain_height": chain_height,
            "current_reward": current_reward,
            "economic_adjustment": economic_adjustment,
            "avg_transactions_per_block": avg_tx_count,
            "avg_transaction_volume": avg_tx_volume,
            "active_miners": active_miners,
            "mining_centralization_index": mining_centralization_index,
            "next_halving_block": next_halving_height,
            "blocks_until_halving": blocks_until_halving,
            "most_active_miner": most_active_miner.map(|(addr, count)| {
                json!({
                    "address": addr,
                    "blocks_mined": count
                })
            }),
        })
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
