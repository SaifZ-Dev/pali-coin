use crate::types::{Block, BlockHeader, Transaction, Hash, Address};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use log::{info, warn, error};
use serde::{Serialize, Deserialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::error::Error;
use std::collections::VecDeque;
use std::str::FromStr;

// Constants for mining rewards, etc.
const MINING_REWARD: u64 = 50;
const UTXO_PREFIX: &[u8] = b"utxo-";
const BLOCKS_DIR: &str = "blocks";
const UTXO_FILE: &str = "utxo.dat";

// The UTXO set is a mapping from addresses to a list of (transaction_hash, amount) pairs
type UtxoSet = HashMap<String, Vec<(Hash, u64)>>;

pub struct Blockchain {
    pub genesis_hash: Hash,
    pub best_hash: Hash,
    pub height: u64,
    pub chain_id: u64,       // Add chain_id to the blockchain
    pub blocks: HashMap<Hash, Block>,
    pub block_hashes: Vec<Hash>,
    data_dir: String,
    pub utxo_set: Arc<RwLock<UtxoSet>>,
    mempool: Arc<RwLock<Vec<Transaction>>>,
    mempool_spending: Arc<RwLock<HashMap<String, u64>>>,
}

impl Blockchain {
pub fn new(data_dir: &str, chain_id: u64) -> Self {
    let data_dir = data_dir.to_string();
    
    // Create data directories if they don't exist
    let blocks_dir = Path::new(&data_dir).join(BLOCKS_DIR);
    if !blocks_dir.exists() {
        fs::create_dir_all(&blocks_dir).expect("Failed to create blocks directory");
    }
    
    // Initialize the blockchain with the genesis block
    let genesis_block = Self::create_genesis_block(chain_id);
    let genesis_hash = genesis_block.hash();
    
    let mut blocks = HashMap::new();
    blocks.insert(genesis_hash, genesis_block);
    
    let mut block_hashes = Vec::new();
    block_hashes.push(genesis_hash);
    
    // Initialize the UTXO set with the genesis block's transactions
    let utxo_set = Self::initialize_utxo_set(&blocks, &genesis_hash);
    
    Blockchain {
        genesis_hash,
        best_hash: genesis_hash,
        height: 0,
        chain_id,
        blocks,
        block_hashes,
        data_dir,
        utxo_set: Arc::new(RwLock::new(utxo_set)),
        mempool: Arc::new(RwLock::new(Vec::new())),
        mempool_spending: Arc::new(RwLock::new(HashMap::new())),
    }
}    
    fn create_genesis_block() -> Block {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        
        let genesis_address = [0u8; 20]; // All zeros address for the genesis block
        
        // Create a coinbase transaction
        let coinbase_tx = Transaction {
            from: [0u8; 20],  // From the "void"
            to: genesis_address,
            amount: MINING_REWARD,
            fee: 0,
            nonce: 0,
            public_key: Vec::new(), // No public key needed for coinbase
            signature: Vec::new(),  // No signature needed for coinbase
        };
        
        let transactions = vec![coinbase_tx];
        
        // Calculate merkle root
        let merkle_root = Self::calculate_merkle_root(&transactions);
        
        // Create the genesis block
        Block {
            header: BlockHeader {
                prev_hash: [0u8; 32],  // Genesis block has all zeros for previous hash
                merkle_root,
                timestamp,
                height: 0,
                nonce: 0,
                difficulty: 1,  // Very easy difficulty for the genesis block
            },
            transactions,
            zk_proof: None,
        }
    }
    
    fn initialize_utxo_set(blocks: &HashMap<Hash, Block>, genesis_hash: &Hash) -> UtxoSet {
        let mut utxo_set = HashMap::new();
        
        // Start with the genesis block
        if let Some(genesis_block) = blocks.get(genesis_hash) {
            for tx in &genesis_block.transactions {
                let recipient = hex::encode(tx.to);
                
                // Create or update the recipient's UTXO list
                let entry = utxo_set.entry(recipient).or_insert_with(Vec::new);
                
                // Add the transaction to the recipient's UTXOs
                entry.push((tx.hash(), tx.amount));
            }
        }
        
        utxo_set
    }
    
    pub fn load(data_dir: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        info!("Loading blockchain from {}", data_dir);
        
        let data_dir_str = data_dir.to_string();
        let blocks_dir = Path::new(data_dir).join(BLOCKS_DIR);
        
        // Create data directories if they don't exist
        if !blocks_dir.exists() {
            fs::create_dir_all(&blocks_dir)?;
            info!("Created blocks directory");
            
            // If the blocks directory didn't exist, initialize a new blockchain
            return Ok(Self::new(data_dir));
        }
        
        // Initialize data structures
        let mut blocks = HashMap::new();
        let mut block_hashes = Vec::new();
        
        // Attempt to load the genesis block first
        let genesis_block = Self::create_genesis_block();
        let genesis_hash = genesis_block.hash();
        
        blocks.insert(genesis_hash, genesis_block);
        block_hashes.push(genesis_hash);
        
        // Attempt to load the UTXO set
        let utxo_path = Path::new(data_dir).join(UTXO_FILE);
        let utxo_set = if utxo_path.exists() {
            let mut file = File::open(&utxo_path)?;
            let mut contents = Vec::new();
            file.read_to_end(&mut contents)?;
            
            serde_json::from_slice(&contents)?
        } else {
            // Initialize the UTXO set with the genesis block's transactions
            Self::initialize_utxo_set(&blocks, &genesis_hash)
        };
        
        // Load all blocks (except genesis which is hardcoded)
        let mut dir_entries = fs::read_dir(&blocks_dir)?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        
        // Sort entries by name to ensure blocks are loaded in order
        dir_entries.sort_by_key(|entry| entry.file_name());
        
        let mut best_hash = genesis_hash;
        let mut height = 0;
        
        for entry in dir_entries {
            let path = entry.path();
            
            if path.is_file() {
                let mut file = File::open(&path)?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                
                let block: Block = serde_json::from_slice(&contents)?;
                let block_hash = block.hash();
                
                if !blocks.contains_key(&block_hash) {
                    blocks.insert(block_hash, block.clone());
                    block_hashes.push(block_hash);
                    
                    // Update best hash and height
                    if block.header.height > height {
                        best_hash = block_hash;
                        height = block.header.height;
                    }
                }
            }
        }
        
        info!("Loaded {} blocks, height: {}", blocks.len(), height);
        
        Ok(Blockchain {
            genesis_hash,
            best_hash,
            height,
            blocks,
            block_hashes,
            data_dir: data_dir_str,
            utxo_set: Arc::new(RwLock::new(utxo_set)),
            mempool: Arc::new(RwLock::new(Vec::new())),
            mempool_spending: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    pub fn save(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!("Saving blockchain to {}", self.data_dir);
        
        let blocks_dir = Path::new(&self.data_dir).join(BLOCKS_DIR);
        if !blocks_dir.exists() {
            fs::create_dir_all(&blocks_dir)?;
        }
        
        // Save the UTXO set
        let utxo_path = Path::new(&self.data_dir).join(UTXO_FILE);
        let utxo_set = self.utxo_set.read().unwrap();
        let serialized = serde_json::to_vec(&*utxo_set)?;
        
        let mut file = File::create(utxo_path)?;
        file.write_all(&serialized)?;
        
        // Save all blocks except the genesis block (which is hardcoded)
        for (hash, block) in &self.blocks {
            if *hash != self.genesis_hash {
                let block_path = blocks_dir.join(format!("{}.json", hex::encode(hash)));
                let serialized = serde_json::to_vec(block)?;
                
                let mut file = File::create(block_path)?;
                file.write_all(&serialized)?;
            }
        }
        
        info!("Blockchain saved successfully");
        Ok(())
    }
    
    fn calculate_merkle_root(transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return [0u8; 32];
        }
        
        if transactions.len() == 1 {
            return transactions[0].hash();
        }
        
        let mut hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();
        
        while hashes.len() > 1 {
            let mut new_hashes = Vec::new();
            
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    // If there's an odd number of hashes, duplicate the last one
                    hasher.update(&chunk[0]);
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
    
    pub fn mine_block(&mut self, miner_address: &Address) -> Result<Block, Box<dyn Error + Send + Sync>> {
        // Create a new block
        let transactions = self.mempool.read().unwrap().clone();
        
        // Validate all transactions in the mempool
        let mut valid_transactions = Vec::new();
        for tx in transactions {
            match self.validate_transaction(&tx) {
                Ok(_) => valid_transactions.push(tx),
                Err(e) => {
                    warn!("Invalid transaction in mempool: {}", e);
                    continue;
                }
            }
        }
        
        // Add a coinbase transaction
        let genesis_transaction = Transaction {
            from: [0u8; 20],  // From the "void"
            to: *miner_address,
            amount: MINING_REWARD,
            fee: 0,
            nonce: self.height + 1,
            public_key: Vec::new(), // No public key needed for coinbase
            signature: Vec::new(),  // No signature needed for coinbase
        };
        
        let mut block_transactions = vec![genesis_transaction];
        block_transactions.extend(valid_transactions);
        
        // Calculate merkle root
        let merkle_root = Self::calculate_merkle_root(&block_transactions);
        
        // Create the block header
        let header = BlockHeader {
            prev_hash: self.best_hash,
            merkle_root,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            height: self.height + 1,
            nonce: 0,
            difficulty: self.calculate_next_difficulty(),
        };
        
        // Create the block
        let mut block = Block {
            header,
            transactions: block_transactions,
            zk_proof: None,
        };
        
        // Mine the block (find a valid nonce)
        self.mine(&mut block)?;
        
        // Add the block to the blockchain
        self.add_block(block.clone())?;
        
        // Clear the mempool
        self.mempool.write().unwrap().clear();
        self.mempool_spending.write().unwrap().clear();
        
        Ok(block)
    }
    
    fn mine(&self, block: &mut Block) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!("Mining block at height {}", block.header.height);
        
        // Adjust the nonce until the block hash meets the difficulty requirement
        while !block.is_valid_proof_of_work() {
            block.header.nonce += 1;
            
            // Every 1000 attempts, print a status update
            if block.header.nonce % 1000 == 0 {
                info!("Mining... nonce: {}", block.header.nonce);
            }
            
            // Avoid infinite loops in testing
            if cfg!(test) && block.header.nonce > 100 {
                block.header.difficulty = 1;
            }
        }
        
        info!("Block mined with nonce: {}", block.header.nonce);
        Ok(())
    }
    
    pub fn add_block(&mut self, block: Block) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_hash = block.hash();
        
        // Validate the block
        self.validate_block(&block)?;
        
        // Update the UTXO set
        self.update_utxo_set(&block)?;
        
        // Add the block to our data structures
        self.blocks.insert(block_hash, block.clone());
        self.block_hashes.push(block_hash);
        
        // Update blockchain state
        self.best_hash = block_hash;
        self.height = block.header.height;
        
        info!("Added block at height {}, hash: {}", self.height, hex::encode(block_hash));
        
        // Save the blockchain state
        self.save()?;
        
        Ok(())
    }
    
    fn validate_block(&self, block: &Block) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Check if the block is already in the blockchain
        let block_hash = block.hash();
        if self.blocks.contains_key(&block_hash) {
            return Err("Block already exists".into());
        }
        
        // Check if the previous block exists
        if !self.blocks.contains_key(&block.header.prev_hash) {
            return Err("Previous block not found".into());
        }
        
        // Check if the height is correct
        let expected_height = match self.blocks.get(&block.header.prev_hash) {
            Some(prev_block) => prev_block.header.height + 1,
            None => return Err("Previous block not found".into()),
        };
        
        if block.header.height != expected_height {
            return Err(format!("Invalid block height: expected {}, got {}", 
                             expected_height, block.header.height).into());
        }
        
        // Check if the merkle root is correct
        let expected_merkle_root = Self::calculate_merkle_root(&block.transactions);
        if block.header.merkle_root != expected_merkle_root {
            return Err("Invalid merkle root".into());
        }
        
        // Check if the block meets the difficulty requirement
        if !block.is_valid_proof_of_work() {
            return Err("Block does not meet difficulty requirement".into());
        }
        
        // Validate all transactions in the block
        for (i, tx) in block.transactions.iter().enumerate() {
            // Skip the coinbase transaction
            if i == 0 && tx.from == [0u8; 20] {
                continue;
            }
            
            match self.validate_transaction(tx) {
                Ok(_) => {},
                Err(e) => return Err(format!("Invalid transaction: {}", e).into()),
            }
        }
        
        Ok(())
    }
    
fn validate_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Skip validation for mining rewards
    if tx.from == [0u8; 20] {
        return Ok(());
    }
    
    // Check chain ID
    if tx.chain_id != self.chain_id {
        return Err(format!("Invalid chain ID: expected {}, got {}", 
                         self.chain_id, tx.chain_id).into());
    }
    
    // Verify transaction signature
    if !tx.verify() {
        return Err("Invalid transaction signature".into());
    }
    
    // Rest of validation remains the same...
}
        
        let sender_balance: u64 = sender_utxos.unwrap().iter()
            .map(|(_, amount)| amount)
            .sum();
        
        if sender_balance < required_amount {
            return Err(format!("Insufficient funds: {} < {}", sender_balance, required_amount).into());
        }
        
        Ok(())
    }
    
    fn update_utxo_set(&self, block: &Block) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut utxo_set = self.utxo_set.write().unwrap();
        
        // Process all transactions in the block
        for tx in &block.transactions {
            // Skip coinbase transactions (they have no inputs)
            if tx.from != [0u8; 20] {
                // Remove the spent UTXOs
                let sender_address = hex::encode(tx.from);
                
                if let Some(sender_utxos) = utxo_set.get_mut(&sender_address) {
                    // Calculate the total amount to be spent
                    let total_spend = tx.amount + tx.fee;
                    
                    // Track spent amount
                    let mut spent = 0;
                    let mut spent_indices = Vec::new();
                    
                    // Find UTXOs to spend
                    for (i, (_, amount)) in sender_utxos.iter().enumerate() {
                        spent += *amount;
                        spent_indices.push(i);
                        
                        if spent >= total_spend {
                            break;
                        }
                    }
                    
                    // Check if we have enough to spend
                    if spent < total_spend {
                        return Err("Insufficient funds".into());
                    }
                    
                    // Calculate change
                    let change = spent - total_spend;
                    
                    // Remove spent UTXOs (in reverse order to avoid index shifting)
                    for i in spent_indices.iter().rev() {
                        sender_utxos.remove(*i);
                    }
                    
                    // Add change back to the sender's UTXOs
                    if change > 0 {
                        sender_utxos.push((tx.hash(), change));
                    }
                    
                    // If the sender has no more UTXOs, remove the entry
                    if sender_utxos.is_empty() {
                        utxo_set.remove(&sender_address);
                    }
                } else {
                    return Err("Sender has no UTXOs".into());
                }
            }
            
            // Add the output to the recipient's UTXOs
            let recipient_address = hex::encode(tx.to);
            let entry = utxo_set.entry(recipient_address).or_insert_with(Vec::new);
            entry.push((tx.hash(), tx.amount));
        }
        
        Ok(())
    }
    
    pub fn get_balance(&self, address: &Address) -> u64 {
        let address_str = hex::encode(address);
        let utxo_set = self.utxo_set.read().unwrap();
        
        if let Some(utxos) = utxo_set.get(&address_str) {
            utxos.iter().map(|(_, amount)| amount).sum()
        } else {
            0
        }
    }
    
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Validate the transaction
        self.validate_transaction(&tx)?;
        
        // Add to the mempool
        let sender_address = hex::encode(tx.from);
        let required_amount = tx.amount + tx.fee;
        
        // Track spending to prevent double spending in the mempool
        let mut mempool_spending = self.mempool_spending.write().unwrap();
        let current_spend = mempool_spending.get(&sender_address).cloned().unwrap_or(0);
        
        // Get the balance from the UTXO set
        let sender_balance = self.get_balance(&tx.from);
        
        // Check if the sender has enough funds considering all transactions in the mempool
        if current_spend + required_amount > sender_balance {
            return Err("Insufficient funds considering mempool transactions".into());
        }
        
        // Update mempool spending
        mempool_spending.insert(sender_address, current_spend + required_amount);
        
        // Add to mempool
        self.mempool.write().unwrap().push(tx);
        
        Ok(())
    }
    
    fn calculate_next_difficulty(&self) -> u32 {
        // In a real implementation, difficulty would be adjusted based on
        // the time it took to mine the last X blocks.
        // For simplicity, we'll just return a fixed difficulty.
        1
    }
    
    pub fn get_transaction_history(&self, address: &Address) -> Vec<Transaction> {
        let address_str = hex::encode(address);
        let mut transactions = Vec::new();
        
        // Scan the entire blockchain for transactions involving this address
        for block in self.blocks.values() {
            for tx in &block.transactions {
                if tx.from == *address || tx.to == *address {
                    transactions.push(tx.clone());
                }
            }
        }
        
        transactions
    }
    
    pub fn get_mempool_transactions(&self) -> Vec<Transaction> {
        self.mempool.read().unwrap().clone()
    }
    
    fn verify_signature(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Coinbase transactions don't need signatures
        if tx.from == [0u8; 20] {
            return Ok(());
        }
        
        // Verify using the Transaction's verify method
        if !tx.verify() {
            return Err("Invalid signature".into());
        }
        
        Ok(())
    }
    
    // Additional methods for more advanced functionality
    // (e.g., handling forks, peer discovery, etc.) would be added here.
}
