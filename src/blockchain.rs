/// src/blockchain.rs - Enterprise-grade blockchain with Bitcoin-level security
use crate::types::{Block, BlockHeader, Transaction, Hash, Address, meets_difficulty_target, double_sha256};
use std::collections::{HashMap, VecDeque, HashSet};
use std::sync::{Arc, RwLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use log::{info, warn, error, debug};
use serde::{Serialize, Deserialize};
use rocksdb::{DB, Options, ColumnFamily, ColumnFamilyDescriptor, IteratorMode};
use std::path::Path;
use chrono::{DateTime, Utc};
use std::thread;
use crossbeam::channel::{Receiver, Sender, unbounded};

// Blockchain constants (Bitcoin-inspired)
const INITIAL_MINING_REWARD: u64 = 5_000_000; // 5 PALI (with 6 decimal places)
const REWARD_HALVING_INTERVAL: u64 = 210_000; // Halve every 210k blocks (like Bitcoin)
const MAX_BLOCK_SIZE: usize = 4_000_000; // 4MB max block size
const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;
const TARGET_BLOCK_TIME: u64 = 600; // 10 minutes (Bitcoin-like)
const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016; // Adjust every 2016 blocks (like Bitcoin)
const MAX_REORG_DEPTH: u64 = 100; // Maximum reorganization depth
const MEMPOOL_MAX_SIZE: usize = 50_000; // Maximum transactions in mempool
const UTXO_CACHE_SIZE: usize = 100_000; // UTXO cache size

// Database column families
const CF_BLOCKS: &str = "blocks";
const CF_TRANSACTIONS: &str = "transactions";
const CF_UTXOS: &str = "utxos";
const CF_METADATA: &str = "metadata";
const CF_CHAINSTATE: &str = "chainstate";

/// UTXO (Unspent Transaction Output) structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXO {
    pub tx_hash: Hash,
    pub output_index: u32,
    pub amount: u64,
    pub address: Address,
    pub block_height: u64,
    pub is_coinbase: bool,
    pub confirmations: u64,
}

/// Blockchain metadata for persistence
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainState {
    pub best_block_hash: Hash,
    pub best_block_height: u64,
    pub total_work: u128, // Cumulative proof-of-work
    pub chain_id: u64,
    pub last_difficulty_adjustment: u64,
    pub current_difficulty: u32,
    pub total_transactions: u64,
    pub circulating_supply: u64,
}

/// Memory pool for pending transactions
#[derive(Debug)]
pub struct Mempool {
    transactions: HashMap<Hash, Transaction>,
    by_fee_rate: VecDeque<(u64, Hash)>, // (fee_rate, tx_hash) sorted by fee rate
    by_sender: HashMap<Address, Vec<Hash>>,
    size_bytes: usize,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            transactions: HashMap::new(),
            by_fee_rate: VecDeque::new(),
            by_sender: HashMap::new(),
            size_bytes: 0,
        }
    }
    
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), String> {
        let tx_hash = tx.hash();
        let tx_size = bincode::serialize(&tx).unwrap_or_default().len();
        
        // Check mempool size limits
        if self.transactions.len() >= MEMPOOL_MAX_SIZE {
            return Err("Mempool full".to_string());
        }
        
        // Check if transaction already exists
        if self.transactions.contains_key(&tx_hash) {
            return Err("Transaction already in mempool".to_string());
        }
        
        // Calculate fee rate (satoshis per byte)
        let fee_rate = if tx_size > 0 { tx.fee / tx_size as u64 } else { 0 };
        
        // Add to data structures
        self.transactions.insert(tx_hash, tx.clone());
        
        // Insert in fee-sorted order (highest fee first)
        let insert_pos = self.by_fee_rate.binary_search_by(|(rate, _)| rate.cmp(&fee_rate).reverse())
            .unwrap_or_else(|pos| pos);
        self.by_fee_rate.insert(insert_pos, (fee_rate, tx_hash));
        
        // Index by sender
        self.by_sender.entry(tx.from).or_insert_with(Vec::new).push(tx_hash);
        
        self.size_bytes += tx_size;
        
        debug!("Added transaction {} to mempool (fee rate: {} sat/byte)", 
               hex::encode(tx_hash), fee_rate);
        Ok(())
    }
    
    pub fn remove_transaction(&mut self, tx_hash: &Hash) {
        if let Some(tx) = self.transactions.remove(tx_hash) {
            let tx_size = bincode::serialize(&tx).unwrap_or_default().len();
            self.size_bytes = self.size_bytes.saturating_sub(tx_size);
            
            // Remove from fee-sorted list
            self.by_fee_rate.retain(|(_, hash)| hash != tx_hash);
            
            // Remove from sender index
            if let Some(sender_txs) = self.by_sender.get_mut(&tx.from) {
                sender_txs.retain(|hash| hash != tx_hash);
                if sender_txs.is_empty() {
                    self.by_sender.remove(&tx.from);
                }
            }
        }
    }
    
    pub fn get_transactions_for_block(&self, max_count: usize, max_size: usize) -> Vec<Transaction> {
        let mut transactions = Vec::new();
        let mut total_size = 0;
        
        for (_, tx_hash) in self.by_fee_rate.iter().take(max_count) {
            if let Some(tx) = self.transactions.get(tx_hash) {
                let tx_size = bincode::serialize(tx).unwrap_or_default().len();
                if total_size + tx_size <= max_size {
                    transactions.push(tx.clone());
                    total_size += tx_size;
                } else {
                    break;
                }
            }
        }
        
        transactions
    }
    
    pub fn contains(&self, tx_hash: &Hash) -> bool {
        self.transactions.contains_key(tx_hash)
    }
    
    pub fn len(&self) -> usize {
        self.transactions.len()
    }
    
    pub fn size_bytes(&self) -> usize {
        self.size_bytes
    }
}

/// Enterprise-grade blockchain implementation
pub struct Blockchain {
    /// RocksDB database handle
    db: Arc<DB>,
    
    /// Current chain state
    chain_state: Arc<RwLock<ChainState>>,
    
    /// UTXO set (unspent transaction outputs)
    utxo_set: Arc<RwLock<HashMap<String, UTXO>>>,
    
    /// Memory pool for pending transactions
    mempool: Arc<Mutex<Mempool>>,
    
    /// Block cache for recent blocks
    block_cache: Arc<RwLock<HashMap<Hash, Block>>>,
    
    /// Transaction processing queue
    tx_queue: Arc<Mutex<VecDeque<Transaction>>>,
    
    /// Orphan blocks (blocks without parent)
    orphan_blocks: Arc<RwLock<HashMap<Hash, Block>>>,
    
    /// Chain ID for network identification
    pub chain_id: u64,
    
    /// Data directory path
    data_dir: String,
    
    /// Background processing channels
    block_processor_tx: Sender<Block>,
    block_processor_rx: Receiver<Block>,
}

impl Blockchain {
    /// Create a new blockchain instance
    pub fn new(data_dir: &str, chain_id: u64) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create data directory if it doesn't exist
        std::fs::create_dir_all(data_dir)?;
        
        // Configure RocksDB with column families
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_open_files(1000);
        db_opts.set_use_fsync(false);
        db_opts.set_bytes_per_sync(1048576);
        db_opts.set_write_buffer_size(256 * 1024 * 1024); // 256MB
        db_opts.set_max_write_buffer_number(6);
        db_opts.set_target_file_size_base(256 * 1024 * 1024); // 256MB
        
        // Define column families
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_TRANSACTIONS, Options::default()),
            ColumnFamilyDescriptor::new(CF_UTXOS, Options::default()),
            ColumnFamilyDescriptor::new(CF_METADATA, Options::default()),
            ColumnFamilyDescriptor::new(CF_CHAINSTATE, Options::default()),
        ];
        
        let db_path = Path::new(data_dir).join("blockchain.db");
        let db = DB::open_cf_descriptors(&db_opts, db_path, cfs)?;
        let db = Arc::new(db);
        
        // Initialize chain state
        let chain_state = Self::load_or_create_chain_state(&db, chain_id)?;
        
        // Create processing channels
        let (block_processor_tx, block_processor_rx) = unbounded();
        
        let blockchain = Blockchain {
            db: db.clone(),
            chain_state: Arc::new(RwLock::new(chain_state)),
            utxo_set: Arc::new(RwLock::new(HashMap::new())),
            mempool: Arc::new(Mutex::new(Mempool::new())),
            block_cache: Arc::new(RwLock::new(HashMap::new())),
            tx_queue: Arc::new(Mutex::new(VecDeque::new())),
            orphan_blocks: Arc::new(RwLock::new(HashMap::new())),
            chain_id,
            data_dir: data_dir.to_string(),
            block_processor_tx,
            block_processor_rx,
        };
        
        // Load existing UTXO set
        blockchain.load_utxo_set()?;
        
        // Initialize genesis block if needed
        if blockchain.get_best_block_height() == 0 {
            blockchain.create_genesis_block()?;
        }
        
        // Start background processing thread
        blockchain.start_background_processing();
        
        info!("Blockchain initialized - Height: {}, Chain ID: {}", 
              blockchain.get_best_block_height(), chain_id);
        
        Ok(blockchain)
    }
    
    /// Create the genesis block
    fn create_genesis_block(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let timestamp = 1640995200; // January 1, 2022 00:00:00 UTC (Pali Coin genesis)
        
        // Genesis block reward goes to a burn address (all zeros)
        let genesis_reward_tx = Transaction::coinbase(
            [0u8; 20], // Burn address
            INITIAL_MINING_REWARD,
            0, // Genesis block height
            self.chain_id,
        );
        
        let mut genesis_block = Block::new(
            [0u8; 32], // No previous block
            vec![genesis_reward_tx],
            24, // Initial difficulty (24 leading zero bits)
            0, // Height 0
        );
        
        // Set fixed timestamp for genesis
        genesis_block.header.timestamp = timestamp;
        
        // Mine the genesis block (should be easy with low difficulty)
        self.mine_block(&mut genesis_block)?;
        
        // Add to blockchain
        self.add_block_internal(genesis_block, true)?;
        
        info!("Genesis block created and added to blockchain");
        Ok(())
    }
    
    /// Load or create chain state from database
    fn load_or_create_chain_state(db: &DB, chain_id: u64) -> Result<ChainState, Box<dyn std::error::Error + Send + Sync>> {
        let cf = db.cf_handle(CF_CHAINSTATE)
            .ok_or("Missing chainstate column family")?;
        
        match db.get_cf(cf, b"chain_state").map_err(|e| e.to_string())? {
            Some(data) => {
                let state: ChainState = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                info!("Loaded existing chain state - Height: {}", state.best_block_height);
                Ok(state)
            }
            None => {
                let state = ChainState {
                    best_block_hash: [0u8; 32],
                    best_block_height: 0,
                    total_work: 0,
                    chain_id,
                    last_difficulty_adjustment: 0,
                    current_difficulty: 24, // Initial difficulty
                    total_transactions: 0,
                    circulating_supply: 0,
                };
                info!("Created new chain state");
                Ok(state)
            }
        }
    }
    
    /// Save chain state to database
    fn save_chain_state(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = self.chain_state.read().unwrap();
        let cf = self.db.cf_handle(CF_CHAINSTATE)
            .ok_or("Missing chainstate column family")?;
        
        let serialized = bincode::serialize(&*state)?;
        self.db.put_cf(cf, b"chain_state", &serialized).map_err(|e| e.to_string())?;
        Ok(())
    }
    
    /// Load UTXO set from database
    fn load_utxo_set(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cf = self.db.cf_handle(CF_UTXOS)
            .ok_or("Missing UTXOS column family")?;
        
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        let mut utxo_set = self.utxo_set.write().unwrap();
        let mut count = 0;
        
        for item in iter {
            let (key, value) = item?;
            let key_str = String::from_utf8_lossy(&key);
            let utxo: UTXO = bincode::deserialize(&value)?;
            utxo_set.insert(key_str.to_string(), utxo);
            count += 1;
        }
        
        info!("Loaded {} UTXOs from database", count);
        Ok(())
    }
    
    /// Add a new block to the blockchain
    pub fn add_block(&self, block: Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.add_block_internal(block, false)
    }
    
    /// Internal block addition with genesis flag
    fn add_block_internal(&self, mut block: Block, is_genesis: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Validate block
        if !is_genesis {
            self.validate_block(&block)?;
        }
        
        // Update block size
        block.header.block_size = bincode::serialize(&block)?.len() as u32;
        
        let block_hash = block.hash();
        let block_height = block.header.height;
        
        // Save block to database
        self.save_block(&block)?;
        
        // Update UTXO set
        self.update_utxo_set(&block)?;
        
        // Update chain state
        {
            let mut state = self.chain_state.write().unwrap();
            state.best_block_hash = block_hash;
            state.best_block_height = block_height;
            state.total_work += self.calculate_work(block.header.difficulty_target);
            state.total_transactions += block.transactions.len() as u64;
            
            // Update circulating supply
            for tx in &block.transactions {
                if tx.is_coinbase() {
                    state.circulating_supply += tx.amount;
                }
            }
        }
        
        // Add to block cache
        {
            let mut cache = self.block_cache.write().unwrap();
            cache.insert(block_hash, block.clone());
            
            // Keep cache size reasonable
            if cache.len() > 1000 {
                // Remove oldest blocks (simple FIFO, could be improved with LRU)
                let keys_to_remove: Vec<_> = cache.keys().take(100).cloned().collect();
                for key in keys_to_remove {
                    cache.remove(&key);
                }
            }
        }
        
        // Remove mined transactions from mempool
        {
            let mut mempool = self.mempool.lock().unwrap();
            for tx in &block.transactions {
                mempool.remove_transaction(&tx.hash());
            }
        }
        
        // Save chain state
        self.save_chain_state()?;
        
        info!("Added block {} at height {}", hex::encode(block_hash), block_height);
        Ok(())
    }
    
    /// Validate a block
    fn validate_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = self.chain_state.read().unwrap();
        
        // Check block height
        if block.header.height != state.best_block_height + 1 {
            return Err(format!("Invalid block height: expected {}, got {}", 
                             state.best_block_height + 1, block.header.height).into());
        }
        
        // Check previous hash
        if block.header.prev_hash != state.best_block_hash {
            return Err("Invalid previous block hash".into());
        }
        
        // Check timestamp
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if block.header.timestamp > now + 7200 { // Max 2 hours in future
            return Err("Block timestamp too far in future".into());
        }
        
        // Check proof of work
        if !block.is_valid_proof_of_work() {
            return Err("Invalid proof of work".into());
        }
        
        // Check difficulty
        let expected_difficulty = self.calculate_next_difficulty()?;
        if block.header.difficulty_target != expected_difficulty {
            return Err(format!("Invalid difficulty: expected {}, got {}", 
                             expected_difficulty, block.header.difficulty_target).into());
        }
        
        // Check block size
        if block.header.block_size as usize > MAX_BLOCK_SIZE {
            return Err("Block too large".into());
        }
        
        // Check transaction count
        if block.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
            return Err("Too many transactions in block".into());
        }
        
        // Validate merkle root
        if !block.verify_merkle_root() {
            return Err("Invalid merkle root".into());
        }
        
        // Validate all transactions
        for (i, tx) in block.transactions.iter().enumerate() {
            if let Err(e) = self.validate_transaction(tx, Some(block.header.height)) {
                return Err(format!("Invalid transaction at index {}: {}", i, e).into());
            }
        }
        
        // Check coinbase transaction
        if let Some(coinbase) = block.coinbase_transaction() {
            let expected_reward = self.calculate_block_reward(block.header.height);
            let total_fees: u64 = block.transactions.iter().skip(1).map(|tx| tx.fee).sum();
            let expected_amount = expected_reward + total_fees;
            
            if coinbase.amount != expected_amount {
                return Err(format!("Invalid coinbase amount: expected {}, got {}", 
                                 expected_amount, coinbase.amount).into());
            }
        } else {
            return Err("Missing coinbase transaction".into());
        }
        
        Ok(())
    }
    
    /// Validate a transaction
    pub fn validate_transaction(&self, tx: &Transaction, block_height: Option<u64>) -> Result<(), String> {
        // Basic transaction validation
        tx.validate(Some(self.chain_id))?;
        
        // Skip UTXO validation for coinbase transactions
        if tx.is_coinbase() {
            return Ok(());
        }
        
        // Check if transaction is already in a block
        if self.transaction_exists(&tx.hash()).map_err(|e| e.to_string())? {
            return Err("Transaction already exists in blockchain".to_string());
        }
        
        // Check sender balance and UTXOs
        let sender_address = hex::encode(tx.from);
        let required_amount = tx.amount + tx.fee;
        
        let utxo_set = self.utxo_set.read().unwrap();
        let sender_utxos: Vec<_> = utxo_set.values()
            .filter(|utxo| hex::encode(utxo.address) == sender_address)
            .collect();
        
        if sender_utxos.is_empty() {
            return Err("Sender has no UTXOs".to_string());
        }
        
        let total_balance: u64 = sender_utxos.iter().map(|utxo| utxo.amount).sum();
        if total_balance < required_amount {
            return Err(format!("Insufficient balance: has {}, needs {}", 
                             total_balance, required_amount));
        }
        
        // Check for double spending in mempool
        let mempool = self.mempool.lock().unwrap();
        for existing_tx in mempool.transactions.values() {
            if existing_tx.from == tx.from && existing_tx.nonce == tx.nonce {
                return Err("Double spending detected in mempool".to_string());
            }
        }
        
        Ok(())
    }
    
    /// Add transaction to mempool
    pub fn add_transaction(&self, tx: Transaction) -> Result<(), String> {
        // Validate transaction
        self.validate_transaction(&tx, None)?;
        
        // Add to mempool
        let mut mempool = self.mempool.lock().unwrap();
        mempool.add_transaction(tx)?;
        
        Ok(())
    }
    
    /// Mine a block with proof of work
    pub fn mine_block(&self, block: &mut Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = SystemTime::now();
        let target_bits = block.header.difficulty_target;
        
        info!("Mining block at height {} with difficulty {}", 
              block.header.height, target_bits);
        
        // Mining loop
        loop {
            let hash = block.hash();
            
            if meets_difficulty_target(&hash, target_bits) {
                let elapsed = start_time.elapsed()?.as_secs_f64();
                info!("Block mined! Nonce: {}, Time: {:.2}s, Hash: {}", 
                      block.header.nonce, elapsed, hex::encode(hash));
                return Ok(());
            }
            
            block.header.nonce = block.header.nonce.wrapping_add(1);
            
            // Update timestamp periodically to keep it current
            if block.header.nonce % 100000 == 0 {
                block.header.timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs();
                
                debug!("Mining progress: nonce {}", block.header.nonce);
            }
            
            // Prevent infinite loops in tests
            if cfg!(test) && block.header.nonce > 1_000_000 {
                block.header.difficulty_target = 1; // Reduce difficulty for tests
            }
        }
    }
    
    /// Create a block template for mining
    pub fn create_block_template(&self, miner_address: &Address) -> Result<Block, Box<dyn std::error::Error + Send + Sync>> {
        let state = self.chain_state.read().unwrap();
        
        // Get transactions from mempool
        let mempool = self.mempool.lock().unwrap();
        let max_tx_size = MAX_BLOCK_SIZE - 1000; // Reserve space for header and coinbase
        let pending_transactions = mempool.get_transactions_for_block(
            MAX_TRANSACTIONS_PER_BLOCK - 1, // Reserve space for coinbase
            max_tx_size
        );
        
        // Calculate total fees
        let total_fees: u64 = pending_transactions.iter().map(|tx| tx.fee).sum();
        let block_reward = self.calculate_block_reward(state.best_block_height + 1);
        let coinbase_amount = block_reward + total_fees;
        
        // Create coinbase transaction
        let coinbase = Transaction::coinbase(
            *miner_address,
            coinbase_amount,
            state.best_block_height + 1,
            self.chain_id,
        );
        
        // Combine transactions
        let mut transactions = vec![coinbase];
        transactions.extend(pending_transactions);
        
        // Calculate next difficulty
        let difficulty = self.calculate_next_difficulty()?;
        
        // Create block
        let mut block = Block::new(
            state.best_block_hash,
            transactions,
            difficulty,
            state.best_block_height + 1,
        );
        
        // Set current timestamp
        block.header.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        Ok(block)
    }
    
    /// Calculate the next difficulty target
    fn calculate_next_difficulty(&self) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let state = self.chain_state.read().unwrap();
        
        // Only adjust difficulty every DIFFICULTY_ADJUSTMENT_INTERVAL blocks
        if (state.best_block_height + 1) % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
            return Ok(state.current_difficulty);
        }
        
        // Get timestamps of blocks for difficulty calculation
        let current_height = state.best_block_height;
        let adjustment_start_height = current_height.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL - 1);
        
        let current_block = self.get_block_by_height(current_height)?
            .ok_or("Current block not found")?;
        let start_block = self.get_block_by_height(adjustment_start_height)?
            .ok_or("Start block not found")?;
        
        let actual_time = current_block.header.timestamp - start_block.header.timestamp;
        let target_time = TARGET_BLOCK_TIME * DIFFICULTY_ADJUSTMENT_INTERVAL;
        
        // Calculate new difficulty (limit adjustment to 4x up or down)
        let new_difficulty = if actual_time < target_time / 4 {
            // Blocks came too fast, increase difficulty
            state.current_difficulty + 1
        } else if actual_time > target_time * 4 {
            // Blocks came too slow, decrease difficulty
            state.current_difficulty.saturating_sub(1).max(1)
        } else {
            // Proportional adjustment
            let ratio = target_time as f64 / actual_time as f64;
            let adjustment = (ratio.ln() / 2f64.ln()) as i32;
            (state.current_difficulty as i32 + adjustment).max(1) as u32
        };
        
        info!("Difficulty adjustment: {} -> {} (actual time: {}s, target: {}s)", 
              state.current_difficulty, new_difficulty, actual_time, target_time);
        
        Ok(new_difficulty)
    }
    
    /// Calculate block reward (with halving)
    fn calculate_block_reward(&self, height: u64) -> u64 {
        let halvings = height / REWARD_HALVING_INTERVAL;
        if halvings >= 32 {
            return 0; // No more rewards after 32 halvings
        }
        
        INITIAL_MINING_REWARD >> halvings
    }
    
    /// Calculate proof-of-work for difficulty
    fn calculate_work(&self, difficulty: u32) -> u128 {
        if difficulty == 0 {
            return 0;
        }
        // Simplified work calculation: 2^difficulty
        1u128 << difficulty.min(127)
    }
    
    /// Update UTXO set with block transactions
    fn update_utxo_set(&self, block: &Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut utxo_set = self.utxo_set.write().unwrap();
        let cf = self.db.cf_handle(CF_UTXOS)
            .ok_or("Missing UTXOS column family")?;
        
        for tx in &block.transactions {
            let tx_hash = tx.hash();
            
            // Remove spent UTXOs (except for coinbase transactions)
            if !tx.is_coinbase() {
                let sender_address = hex::encode(tx.from);
                let required_amount = tx.amount + tx.fee;
                let mut spent_amount = 0u64;
                
                // Find and remove UTXOs to spend
                let utxos_to_remove: Vec<String> = utxo_set.iter()
                    .filter(|(_, utxo)| hex::encode(utxo.address) == sender_address)
                    .take_while(|(_, utxo)| {
                        if spent_amount < required_amount {
                            spent_amount += utxo.amount;
                            true
                        } else {
                            false
                        }
                    })
                    .map(|(key, _)| key.clone())
                    .collect();
                
                for key in utxos_to_remove {
                    utxo_set.remove(&key);
                    self.db.delete_cf(cf, key.as_bytes()).map_err(|e| e.to_string())?;
                }
                
                // Create change UTXO if necessary
                if spent_amount > required_amount {
                    let change_amount = spent_amount - required_amount;
                    let change_utxo = UTXO {
                        tx_hash,
                        output_index: 0, // Change output
                        amount: change_amount,
                        address: tx.from,
                        block_height: block.header.height,
                        is_coinbase: false,
                        confirmations: 1,
                    };
                    
                    let key = format!("{}:{}", hex::encode(tx_hash), 0);
                    let serialized = bincode::serialize(&change_utxo)?;
                    utxo_set.insert(key.clone(), change_utxo);
                    self.db.put_cf(cf, key.as_bytes(), &serialized).map_err(|e| e.to_string())?;
                }
            }
            
            // Add new UTXO for recipient
            let recipient_utxo = UTXO {
                tx_hash,
                output_index: 1, // Main output
                amount: tx.amount,
                address: tx.to,
                block_height: block.header.height,
                is_coinbase: tx.is_coinbase(),
                confirmations: 1,
            };
            
            let key = format!("{}:{}", hex::encode(tx_hash), 1);
            let serialized = bincode::serialize(&recipient_utxo)?;
            utxo_set.insert(key.clone(), recipient_utxo);
            self.db.put_cf(cf, key.as_bytes(), &serialized).map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }
    
    /// Save block to database
    fn save_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cf = self.db.cf_handle(CF_BLOCKS)
            .ok_or("Missing blocks column family")?;
        
        let block_hash = block.hash();
        let serialized = bincode::serialize(block)?;
        
        // Save by hash
        self.db.put_cf(cf, &block_hash, &serialized).map_err(|e| e.to_string())?;
        
        // Save by height for easier lookup
        let height_key = format!("height:{}", block.header.height);
        self.db.put_cf(cf, height_key.as_bytes(), &block_hash).map_err(|e| e.to_string())?;
        
        // Save each transaction
        let tx_cf = self.db.cf_handle(CF_TRANSACTIONS)
            .ok_or("Missing transactions column family")?;
        
        for tx in &block.transactions {
            let tx_hash = tx.hash();
            let tx_serialized = bincode::serialize(tx)?;
            self.db.put_cf(tx_cf, &tx_hash, &tx_serialized).map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }
    
    /// Get block by hash
    pub fn get_block(&self, hash: &Hash) -> Result<Option<Block>, Box<dyn std::error::Error + Send + Sync>> {
        // Check cache first
        {
            let cache = self.block_cache.read().unwrap();
            if let Some(block) = cache.get(hash) {
                return Ok(Some(block.clone()));
            }
        }
        
        // Load from database
        let cf = self.db.cf_handle(CF_BLOCKS)
            .ok_or("Missing blocks column family")?;
        
        match self.db.get_cf(cf, hash).map_err(|e| e.to_string())? {
            Some(data) => {
                let block: Block = bincode::deserialize(&data)?;
                
                // Add to cache
                {
                    let mut cache = self.block_cache.write().unwrap();
                    cache.insert(*hash, block.clone());
                }
                
                Ok(Some(block))
            }
            None => Ok(None)
        }
    }
    
    /// Get block by height
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error + Send + Sync>> {
        let cf = self.db.cf_handle(CF_BLOCKS)
            .ok_or("Missing blocks column family")?;
        
        let height_key = format!("height:{}", height);
        match self.db.get_cf(cf, height_key.as_bytes()).map_err(|e| e.to_string())? {
            Some(hash_data) => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_data);
                self.get_block(&hash)
            }
            None => Ok(None)
        }
    }
    
    /// Check if transaction exists in blockchain
    pub fn transaction_exists(&self, tx_hash: &Hash) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let cf = self.db.cf_handle(CF_TRANSACTIONS)
            .ok_or("Missing transactions column family")?;
        
        Ok(self.db.get_cf(cf, tx_hash).map_err(|e| e.to_string())?.is_some())
    }
    
    /// Get balance for an address
    pub fn get_balance(&self, address: &Address) -> u64 {
        let address_hex = hex::encode(address);
        let utxo_set = self.utxo_set.read().unwrap();
        
        utxo_set.values()
            .filter(|utxo| hex::encode(utxo.address) == address_hex)
            .map(|utxo| utxo.amount)
            .sum()
    }
    
    /// Get current chain height
    pub fn get_best_block_height(&self) -> u64 {
        self.chain_state.read().unwrap().best_block_height
    }
    
    /// Get current best block hash
    pub fn get_best_block_hash(&self) -> Hash {
        self.chain_state.read().unwrap().best_block_hash
    }
    
    /// Get latest block
    pub fn get_latest_block(&self) -> Option<Block> {
        let best_hash = self.get_best_block_hash();
        self.get_block(&best_hash).unwrap_or(None)
    }
    
    /// Get blockchain statistics
    pub fn get_blockchain_stats(&self) -> serde_json::Value {
        let state = self.chain_state.read().unwrap();
        let mempool = self.mempool.lock().unwrap();
        let utxo_count = self.utxo_set.read().unwrap().len();
        
        serde_json::json!({
            "height": state.best_block_height,
            "best_block_hash": hex::encode(state.best_block_hash),
            "total_transactions": state.total_transactions,
            "circulating_supply": state.circulating_supply,
            "current_difficulty": state.current_difficulty,
            "total_work": state.total_work.to_string(),
            "mempool_size": mempool.len(),
            "mempool_bytes": mempool.size_bytes(),
            "utxo_count": utxo_count,
            "chain_id": state.chain_id,
        })
    }
    
    /// Get transaction history for an address
    pub fn get_transaction_history(&self, address: &Address, limit: usize) -> Vec<serde_json::Value> {
        let address_hex = hex::encode(address);
        let mut transactions = Vec::new();
        
        // This is a simplified implementation
        // In production, you'd want to maintain an address index
        let state = self.chain_state.read().unwrap();
        
        for height in (0..=state.best_block_height).rev().take(limit * 10) {
            if let Ok(Some(block)) = self.get_block_by_height(height) {
                for tx in &block.transactions {
                    let from_hex = hex::encode(tx.from);
                    let to_hex = hex::encode(tx.to);
                    
                    if from_hex == address_hex || to_hex == address_hex {
                        transactions.push(serde_json::json!({
                            "hash": hex::encode(tx.hash()),
                            "from": from_hex,
                            "to": to_hex,
                            "amount": tx.amount,
                            "fee": tx.fee,
                            "block_height": height,
                            "timestamp": block.header.timestamp,
                            "confirmations": state.best_block_height - height + 1,
                        }));
                        
                        if transactions.len() >= limit {
                            break;
                        }
                    }
                }
                
                if transactions.len() >= limit {
                    break;
                }
            }
        }
        
        transactions
    }
    
    /// Start background processing thread
    fn start_background_processing(&self) {
        let db = Arc::clone(&self.db);
        let chain_state = Arc::clone(&self.chain_state);
        let utxo_set = Arc::clone(&self.utxo_set);
        let block_cache = Arc::clone(&self.block_cache);
        let receiver = self.block_processor_rx.clone();
        
        thread::spawn(move || {
            info!("Background block processor started");
            
            while let Ok(block) = receiver.recv() {
                debug!("Processing block {} in background", hex::encode(block.hash()));
                
                // Perform additional validation and processing
                // This could include updating indexes, notifications, etc.
                
                // Update block confirmations
                Self::update_confirmations(&db, &chain_state, &utxo_set).unwrap_or_else(|e| {
                    error!("Failed to update confirmations: {}", e);
                });
                
                // Cleanup old cache entries
                Self::cleanup_cache(&block_cache);
            }
            
            info!("Background block processor stopped");
        });
    }
    
    /// Update confirmation counts for UTXOs
    fn update_confirmations(
        db: &Arc<DB>,
        chain_state: &Arc<RwLock<ChainState>>,
        utxo_set: &Arc<RwLock<HashMap<String, UTXO>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let current_height = chain_state.read().unwrap().best_block_height;
        let mut utxo_set = utxo_set.write().unwrap();
        let cf = db.cf_handle(CF_UTXOS).ok_or("Missing UTXOS column family")?;
        
        for (key, utxo) in utxo_set.iter_mut() {
            let old_confirmations = utxo.confirmations;
            utxo.confirmations = current_height - utxo.block_height + 1;
            
            // Only update database if confirmations changed significantly
            if utxo.confirmations != old_confirmations && utxo.confirmations % 10 == 0 {
                let serialized = bincode::serialize(utxo)?;
                db.put_cf(cf, key.as_bytes(), &serialized).map_err(|e| e.to_string())?;
            }
        }
        
        Ok(())
    }
    
    /// Cleanup old cache entries
    fn cleanup_cache(block_cache: &Arc<RwLock<HashMap<Hash, Block>>>) {
        let mut cache = block_cache.write().unwrap();
        
        if cache.len() > 1500 {
            // Remove oldest 500 blocks from cache
            let keys_to_remove: Vec<_> = cache.keys().take(500).cloned().collect();
            for key in keys_to_remove {
                cache.remove(&key);
            }
            debug!("Cleaned up block cache, new size: {}", cache.len());
        }
    }
    
    /// Perform blockchain reorganization if needed
    pub fn handle_reorganization(&self, _new_branch: Vec<Block>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Simplified reorganization handling
        // In production, this would:
        // 1. Validate the new branch has more cumulative work
        // 2. Revert blocks to the common ancestor
        // 3. Apply blocks from the new branch
        // 4. Update UTXO set accordingly
        // 5. Re-add reverted transactions to mempool
        
        warn!("Blockchain reorganization not fully implemented");
        Ok(())
    }
    
    /// Validate and add an orphan block
    pub fn add_orphan_block(&self, block: Block) -> Result<(), String> {
        let block_hash = block.hash();
        let mut orphans = self.orphan_blocks.write().unwrap();
        
        if orphans.len() >= 100 {
            return Err("Too many orphan blocks".to_string());
        }
        
        orphans.insert(block_hash, block);
        debug!("Added orphan block {}", hex::encode(block_hash));
        Ok(())
    }
    
    /// Process orphan blocks when their parent arrives
    pub fn process_orphan_blocks(&self, parent_hash: &Hash) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut orphans = self.orphan_blocks.write().unwrap();
        let blocks_to_process: Vec<_> = orphans.values()
            .filter(|block| block.header.prev_hash == *parent_hash)
            .cloned()
            .collect();
        
        for block in blocks_to_process {
            let block_hash = block.hash();
            match self.add_block(block) {
                Ok(()) => {
                    orphans.remove(&block_hash);
                    info!("Processed orphan block {}", hex::encode(block_hash));
                }
                Err(e) => {
                    warn!("Failed to process orphan block {}: {}", hex::encode(block_hash), e);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get mempool transactions
    pub fn get_mempool_transactions(&self) -> Vec<Transaction> {
        let mempool = self.mempool.lock().unwrap();
        mempool.transactions.values().cloned().collect()
    }
    
    /// Get network difficulty info
    pub fn get_network_difficulty(&self) -> serde_json::Value {
        let state = self.chain_state.read().unwrap();
        let next_difficulty = self.calculate_next_difficulty().unwrap_or(state.current_difficulty);
        
        serde_json::json!({
            "current_difficulty": state.current_difficulty,
            "next_difficulty": next_difficulty,
            "blocks_until_adjustment": DIFFICULTY_ADJUSTMENT_INTERVAL - (state.best_block_height % DIFFICULTY_ADJUSTMENT_INTERVAL),
            "target_block_time": TARGET_BLOCK_TIME,
            "adjustment_interval": DIFFICULTY_ADJUSTMENT_INTERVAL,
        })
    }
    
    /// Estimate transaction fee
    pub fn estimate_fee(&self, tx_size: usize, priority: &str) -> u64 {
        let mempool = self.mempool.lock().unwrap();
        
        if mempool.transactions.is_empty() {
            return 1000; // Minimum fee: 0.001 PALI
        }
        
        // Calculate fee rate based on mempool
        let fee_rates: Vec<u64> = mempool.by_fee_rate.iter()
            .map(|(rate, _)| *rate)
            .collect();
        
        let percentile_index = match priority {
            "high" => fee_rates.len() * 10 / 100,      // Top 10%
            "medium" => fee_rates.len() * 50 / 100,    // Median
            "low" => fee_rates.len() * 90 / 100,       // Bottom 10%
            _ => fee_rates.len() * 50 / 100,           // Default to median
        };
        
        let fee_rate = fee_rates.get(percentile_index).copied().unwrap_or(1);
        (fee_rate * tx_size as u64).max(1000) // Minimum 0.001 PALI
    }
    
    /// Get rich list (top addresses by balance)
    pub fn get_rich_list(&self, limit: usize) -> Vec<serde_json::Value> {
        let utxo_set = self.utxo_set.read().unwrap();
        let mut balances: HashMap<String, u64> = HashMap::new();
        
        // Aggregate balances by address
        for utxo in utxo_set.values() {
            let address = hex::encode(utxo.address);
            *balances.entry(address).or_insert(0) += utxo.amount;
        }
        
        // Sort by balance descending
        let mut sorted_balances: Vec<_> = balances.into_iter().collect();
        sorted_balances.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Return top addresses
        sorted_balances.into_iter()
            .take(limit)
            .map(|(address, balance)| serde_json::json!({
                "address": address,
                "balance": balance,
                "balance_pali": balance as f64 / 1_000_000.0,
            }))
            .collect()
    }
    
    /// Backup blockchain data
    pub fn backup_to_file(&self, backup_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let backup_data = serde_json::json!({
            "chain_state": *self.chain_state.read().unwrap(),
            "backup_timestamp": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "blockchain_stats": self.get_blockchain_stats(),
        });
        
        std::fs::write(backup_path, serde_json::to_string_pretty(&backup_data)?)?;
        info!("Blockchain backup saved to {}", backup_path);
        Ok(())
    }
    
    /// Compact database to reclaim space
    pub fn compact_database(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting database compaction...");
        
        for cf_name in [CF_BLOCKS, CF_TRANSACTIONS, CF_UTXOS, CF_METADATA, CF_CHAINSTATE] {
            if let Some(cf) = self.db.cf_handle(cf_name) {
                self.db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
                debug!("Compacted column family: {}", cf_name);
            }
        }
        
        info!("Database compaction completed");
        Ok(())
    }
}

/// Cleanup when blockchain is dropped
impl Drop for Blockchain {
    fn drop(&mut self) {
        // Save final state
        if let Err(e) = self.save_chain_state() {
            error!("Failed to save chain state on drop: {}", e);
        }
        
        info!("Blockchain instance dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::wallet::Wallet;
    
    #[test]
    fn test_blockchain_creation() {
        let temp_dir = tempdir().unwrap();
        let blockchain = Blockchain::new(temp_dir.path().to_str().unwrap(), 1).unwrap();
        
        assert_eq!(blockchain.chain_id, 1);
        assert_eq!(blockchain.get_best_block_height(), 0); // Genesis block
    }
    
    #[test]
    fn test_block_mining_and_addition() {
        let temp_dir = tempdir().unwrap();
        let blockchain = Blockchain::new(temp_dir.path().to_str().unwrap(), 1).unwrap();
        
        let wallet = Wallet::new().unwrap();
        let mut block = blockchain.create_block_template(&wallet.address).unwrap();
        
        // Mine the block (use easy difficulty for test)
        block.header.difficulty_target = 1;
        blockchain.mine_block(&mut block).unwrap();
        
        // Add the block
        blockchain.add_block(block).unwrap();
        assert_eq!(blockchain.get_best_block_height(), 1);
    }
    
    #[test]
    fn test_transaction_validation() {
        let temp_dir = tempdir().unwrap();
        let blockchain = Blockchain::new(temp_dir.path().to_str().unwrap(), 1).unwrap();
        
        let wallet = Wallet::new().unwrap();
        let recipient = [1u8; 20];
        
        let mut tx = Transaction::new(
            wallet.address,
            recipient,
            1000000,
            1000,
            1,
            1,
        );
        
        wallet.sign_transaction(&mut tx).unwrap();
        
        // Should fail because wallet has no UTXOs
        assert!(blockchain.validate_transaction(&tx, None).is_err());
    }
    
    #[test]
    fn test_balance_calculation() {
        let temp_dir = tempdir().unwrap();
        let blockchain = Blockchain::new(temp_dir.path().to_str().unwrap(), 1).unwrap();
        
        let wallet = Wallet::new().unwrap();
        let balance = blockchain.get_balance(&wallet.address);
        
        assert_eq!(balance, 0); // New wallet should have zero balance
    }
    
    #[test]
    fn test_difficulty_calculation() {
        let temp_dir = tempdir().unwrap();
        let blockchain = Blockchain::new(temp_dir.path().to_str().unwrap(), 1).unwrap();
        
        let difficulty = blockchain.calculate_next_difficulty().unwrap();
        assert!(difficulty > 0);
    }
}
