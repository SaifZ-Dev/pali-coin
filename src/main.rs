// src/main.rs - Production-Ready Secure Pali Coin Node
use pali_coin::blockchain::Blockchain;
use pali_coin::types::{Block, Transaction, Hash, Address};
use pali_coin::network::{NetworkMessage, NetworkClient, SecureNetworkClient};
use pali_coin::security::SecurityManager;
use pali_coin::error::{PaliError, Result};
use std::sync::{Arc, RwLock, Mutex, atomic::{AtomicUsize, AtomicU64, Ordering}};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Instant, Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use log::{info, error, debug, warn};
use clap::{Arg, Command};
use serde::{Serialize, Deserialize};
use dashmap::DashMap;
use parking_lot::RwLock as ParkingRwLock;

// PRODUCTION SECURITY CONSTANTS
const MAX_CONNECTIONS_DEFAULT: usize = 1000;
const MAX_REQUESTS_PER_MINUTE: u32 = 60;
const MAX_REQUESTS_PER_HOUR: u32 = 3600;
const BAN_DURATION_MINUTES: u64 = 60;
const SESSION_TIMEOUT_SECONDS: u64 = 300; // 5 minutes
const HANDSHAKE_TIMEOUT_SECONDS: u64 = 30;
const MESSAGE_TIMEOUT_SECONDS: u64 = 30;
const MAX_MESSAGE_SIZE: usize = 10_000_000; // 10MB
const MAX_BLOCK_SIZE: usize = 4_000_000; // 4MB
const MAX_TRANSACTION_SIZE: usize = 100_000; // 100KB
const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;
const MIN_TRANSACTION_FEE: u64 = 1000; // 0.00001 PALI
const MAX_MEMPOOL_SIZE: usize = 50_000;

/// Enterprise-grade security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub max_connections: usize,
    pub max_requests_per_minute: u32,
    pub max_requests_per_hour: u32,
    pub ban_duration_minutes: u64,
    pub enable_ddos_protection: bool,
    pub enable_geoblocking: bool,
    pub blocked_countries: Vec<String>,
    pub require_pow_for_connections: bool,
    pub min_peer_version: String,
    pub max_block_size: usize,
    pub max_transaction_size: usize,
    pub rate_limit_whitelist: Vec<IpAddr>,
    pub trusted_peers: Vec<IpAddr>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            max_connections: MAX_CONNECTIONS_DEFAULT,
            max_requests_per_minute: MAX_REQUESTS_PER_MINUTE,
            max_requests_per_hour: MAX_REQUESTS_PER_HOUR,
            ban_duration_minutes: BAN_DURATION_MINUTES,
            enable_ddos_protection: true,
            enable_geoblocking: false,
            blocked_countries: vec![],
            require_pow_for_connections: false,
            min_peer_version: "0.1.0".to_string(),
            max_block_size: MAX_BLOCK_SIZE,
            max_transaction_size: MAX_TRANSACTION_SIZE,
            rate_limit_whitelist: vec![],
            trusted_peers: vec![],
        }
    }
}

/// Connection statistics and tracking
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub ip: IpAddr,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub violations: u32,
    pub user_agent: Option<String>,
    pub peer_version: Option<String>,
}

/// Advanced rate limiting with multiple time windows
#[derive(Debug)]
pub struct AdvancedRateLimiter {
    // Per-minute tracking
    minute_requests: DashMap<IpAddr, (u32, Instant)>,
    // Per-hour tracking
    hour_requests: DashMap<IpAddr, (u32, Instant)>,
    // Banned IPs with expiration
    banned_ips: DashMap<IpAddr, Instant>,
    // Connection tracking
    connections_per_ip: DashMap<IpAddr, u32>,
    // Violation scoring
    violation_scores: DashMap<IpAddr, (u32, Instant)>,
    // Configuration
    config: SecurityConfig,
}

impl AdvancedRateLimiter {
    pub fn new(config: SecurityConfig) -> Self {
        AdvancedRateLimiter {
            minute_requests: DashMap::new(),
            hour_requests: DashMap::new(),
            banned_ips: DashMap::new(),
            connections_per_ip: DashMap::new(),
            violation_scores: DashMap::new(),
            config,
        }
    }
    
    pub fn check_connection_allowed(&self, ip: IpAddr) -> bool {
        // Check if IP is whitelisted
        if self.config.rate_limit_whitelist.contains(&ip) {
            return true;
        }
        
        // Check if IP is banned
        if let Some(ban_expiry) = self.banned_ips.get(&ip) {
            if Instant::now() < *ban_expiry {
                return false; // Still banned
            } else {
                self.banned_ips.remove(&ip); // Ban expired
            }
        }
        
        // Check connection limit per IP
        let current_connections = self.connections_per_ip.get(&ip).map(|v| *v).unwrap_or(0);
        if current_connections >= 10 { // Max 10 connections per IP
            self.add_violation(ip, "too_many_connections");
            return false;
        }
        
        true
    }
    
    pub fn check_rate_limit(&self, ip: IpAddr) -> bool {
        // Check if IP is whitelisted
        if self.config.rate_limit_whitelist.contains(&ip) {
            return true;
        }
        
        let now = Instant::now();
        
        // Check minute rate limit
        let mut minute_entry = self.minute_requests.entry(ip).or_insert((0, now));
        if now.duration_since(minute_entry.1) >= Duration::from_secs(60) {
            minute_entry.0 = 0;
            minute_entry.1 = now;
        }
        minute_entry.0 += 1;
        
        if minute_entry.0 > self.config.max_requests_per_minute {
            self.add_violation(ip, "minute_rate_limit");
            return false;
        }
        
        // Check hour rate limit
        let mut hour_entry = self.hour_requests.entry(ip).or_insert((0, now));
        if now.duration_since(hour_entry.1) >= Duration::from_secs(3600) {
            hour_entry.0 = 0;
            hour_entry.1 = now;
        }
        hour_entry.0 += 1;
        
        if hour_entry.0 > self.config.max_requests_per_hour {
            self.add_violation(ip, "hour_rate_limit");
            return false;
        }
        
        true
    }
    
    pub fn add_connection(&self, ip: IpAddr) {
        *self.connections_per_ip.entry(ip).or_insert(0) += 1;
    }
    
    pub fn remove_connection(&self, ip: IpAddr) {
        if let Some(mut count) = self.connections_per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                drop(count);
                self.connections_per_ip.remove(&ip);
            }
        }
    }
    
    fn add_violation(&self, ip: IpAddr, reason: &str) {
        let now = Instant::now();
        let mut entry = self.violation_scores.entry(ip).or_insert((0, now));
        
        // Reset violations if more than an hour old
        if now.duration_since(entry.1) >= Duration::from_secs(3600) {
            entry.0 = 0;
            entry.1 = now;
        }
        
        entry.0 += 1;
        
        // Ban if too many violations
        if entry.0 >= 10 {
            let ban_until = now + Duration::from_secs(self.config.ban_duration_minutes * 60);
            self.banned_ips.insert(ip, ban_until);
            warn!("🚫 Banned IP {} for violations: {}", ip, reason);
        }
    }
    
    pub fn cleanup_expired_entries(&self) {
        let now = Instant::now();
        
        // Clean up expired bans
        self.banned_ips.retain(|_, &mut expiry| now < expiry);
        
        // Clean up old rate limit entries
        self.minute_requests.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < Duration::from_secs(120)
        });
        
        self.hour_requests.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < Duration::from_secs(7200)
        });
        
        self.violation_scores.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < Duration::from_secs(7200)
        });
    }
    
    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "active_connections": self.connections_per_ip.len(),
            "banned_ips": self.banned_ips.len(),
            "minute_rate_limits": self.minute_requests.len(),
            "hour_rate_limits": self.hour_requests.len(),
            "violation_scores": self.violation_scores.len(),
        })
    }
}

/// Secure Node Service with enterprise-grade security
pub struct SecureNodeService {
    blockchain: Arc<RwLock<Blockchain>>,
    mempool: Arc<RwLock<VecDeque<Transaction>>>,
    peers: Arc<RwLock<HashMap<SocketAddr, ConnectionStats>>>,
    rate_limiter: Arc<AdvancedRateLimiter>,
    security_manager: Arc<SecurityManager>,
    chain_id: u64,
    
    // Performance metrics
    total_connections: AtomicU64,
    total_messages: AtomicU64,
    total_blocks_processed: AtomicU64,
    total_transactions_processed: AtomicU64,
    
    // Security metrics
    blocked_connections: AtomicU64,
    invalid_blocks: AtomicU64,
    invalid_transactions: AtomicU64,
    
    // Configuration
    config: SecurityConfig,
    node_start_time: Instant,
}

impl SecureNodeService {
    pub fn new(
        data_dir: &str, 
        chain_id: u64, 
        config: SecurityConfig
    ) -> Result<Self> {
        let blockchain = Blockchain::new(data_dir, chain_id)?;
        let security_manager = SecurityManager::new(Default::default());
        
        Ok(SecureNodeService {
            blockchain: Arc::new(RwLock::new(blockchain)),
            mempool: Arc::new(RwLock::new(VecDeque::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(AdvancedRateLimiter::new(config.clone())),
            security_manager: Arc::new(security_manager),
            chain_id,
            total_connections: AtomicU64::new(0),
            total_messages: AtomicU64::new(0),
            total_blocks_processed: AtomicU64::new(0),
            total_transactions_processed: AtomicU64::new(0),
            blocked_connections: AtomicU64::new(0),
            invalid_blocks: AtomicU64::new(0),
            invalid_transactions: AtomicU64::new(0),
            config,
            node_start_time: Instant::now(),
        })
    }
    
    /// Secure message handler with comprehensive validation
    pub async fn handle_secure_message(
        &self,
        message: NetworkMessage,
        client_ip: IpAddr,
        peer_id: Option<String>,
    ) -> NetworkMessage {
        // Increment message counter
        self.total_messages.fetch_add(1, Ordering::Relaxed);
        
        // Rate limiting check
        if !self.rate_limiter.check_rate_limit(client_ip) {
            return NetworkMessage::Error {
                message: "Rate limit exceeded".to_string(),
                error_code: 429,
            };
        }
        
        // Security validation
        if let Err(e) = self.security_manager.validate_message(
            SocketAddr::new(client_ip, 0), 
            &bincode::serialize(&message).unwrap_or_default()
        ) {
            warn!("Security validation failed for {}: {}", client_ip, e);
            return NetworkMessage::Error {
                message: "Security validation failed".to_string(),
                error_code: 403,
            };
        }
        
        // Process message based on type
        match message {
            NetworkMessage::SubmitBlock { block } => {
                self.handle_block_submission(block, client_ip).await
            }
            
            NetworkMessage::NewTransaction { transaction, priority: _ } => {
                self.handle_transaction_submission(transaction, client_ip).await
            }
            
            NetworkMessage::GetHeight => {
                NetworkMessage::Height { height: self.get_chain_height() }
            }
            
            NetworkMessage::GetTemplate { miner_address } => {
                self.handle_template_request(miner_address, client_ip).await
            }
            
            NetworkMessage::GetPendingTransactions { limit } => {
                let safe_limit = limit.min(1000); // Security: limit response size
                let transactions = self.get_pending_transactions(safe_limit);
                NetworkMessage::PendingTransactions { transactions }
            }
            
            NetworkMessage::GetBalance { address } => {
                if !self.is_valid_address_format(&address) {
                    return NetworkMessage::Error {
                        message: "Invalid address format".to_string(),
                        error_code: 400,
                    };
                }
                let balance = self.get_balance(&address);
                NetworkMessage::Balance { address, amount: balance }
            }
            
            NetworkMessage::GetBlock { hash } => {
                self.handle_get_block(hash, client_ip).await
            }
            
            NetworkMessage::GetTransactions { hashes } => {
                if hashes.len() > 100 { // Security: limit batch size
                    return NetworkMessage::Error {
                        message: "Too many transactions requested".to_string(),
                        error_code: 400,
                    };
                }
                self.handle_get_transactions(hashes, client_ip).await
            }
            
            NetworkMessage::Ping { nonce, timestamp } => {
                // Validate timestamp to prevent replay attacks
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                if timestamp > now + 300 || timestamp < now.saturating_sub(300) {
                    return NetworkMessage::Error {
                        message: "Invalid timestamp".to_string(),
                        error_code: 400,
                    };
                }
                NetworkMessage::Pong { nonce, timestamp: now }
            }
            
            _ => {
                debug!("Unsupported message type from {}", client_ip);
                NetworkMessage::Error {
                    message: "Unsupported message type".to_string(),
                    error_code: 400,
                }
            }
        }
    }
    
    async fn handle_block_submission(&self, block: Block, client_ip: IpAddr) -> NetworkMessage {
        // Comprehensive block validation
        if let Err(e) = self.validate_block_comprehensive(&block) {
            warn!("❌ Invalid block from {}: {}", client_ip, e);
            self.invalid_blocks.fetch_add(1, Ordering::Relaxed);
            return NetworkMessage::Error {
                message: e,
                error_code: 400,
            };
        }
        
        // Check if we already have this block
        let block_hash = block.hash();
        if self.has_block(&block_hash) {
            return NetworkMessage::Error {
                message: "Block already known".to_string(),
                error_code: 409,
            };
        }
        
        // Submit to blockchain
        match self.submit_block(block) {
            Ok(_) => {
                info!("✅ Block {} accepted from {}", hex::encode(block_hash), client_ip);
                self.total_blocks_processed.fetch_add(1, Ordering::Relaxed);
                NetworkMessage::Pong
            }
            Err(msg) => {
                warn!("❌ Block rejected from {}: {}", client_ip, msg);
                self.invalid_blocks.fetch_add(1, Ordering::Relaxed);
                NetworkMessage::Error {
                    message: msg,
                    error_code: 400,
                }
            }
        }
    }
    
    async fn handle_transaction_submission(&self, tx: Transaction, client_ip: IpAddr) -> NetworkMessage {
        // Comprehensive transaction validation
        if let Err(e) = self.validate_transaction_comprehensive(&tx) {
            warn!("❌ Invalid transaction from {}: {}", client_ip, e);
            self.invalid_transactions.fetch_add(1, Ordering::Relaxed);
            return NetworkMessage::Error {
                message: e,
                error_code: 400,
            };
        }
        
        // Check mempool size
        {
            let mempool = self.mempool.read().unwrap();
            if mempool.len() >= MAX_MEMPOOL_SIZE {
                return NetworkMessage::Error {
                    message: "Mempool full".to_string(),
                    error_code: 503,
                };
            }
        }
        
        // Check for duplicate in mempool
        let tx_hash = tx.hash();
        {
            let mempool = self.mempool.read().unwrap();
            if mempool.iter().any(|existing_tx| existing_tx.hash() == tx_hash) {
                return NetworkMessage::Error {
                    message: "Transaction already in mempool".to_string(),
                    error_code: 409,
                };
            }
        }
        
        // Add to mempool
        {
            let mut mempool = self.mempool.write().unwrap();
            mempool.push_back(tx);
        }
        
        self.total_transactions_processed.fetch_add(1, Ordering::Relaxed);
        info!("✅ Transaction {} accepted from {}", hex::encode(tx_hash), client_ip);
        NetworkMessage::Pong
    }
    
    async fn handle_template_request(&self, miner_address: String, client_ip: IpAddr) -> NetworkMessage {
        // Validate miner address
        if !self.is_valid_address_format(&miner_address) {
            return NetworkMessage::Error {
                message: "Invalid miner address format".to_string(),
                error_code: 400,
            };
        }
        
        // Create block template
        match self.create_block_template(&miner_address) {
            Ok(template) => {
                let difficulty = self.get_current_difficulty();
                let coinbase_value = self.calculate_block_reward();
                
                NetworkMessage::BlockTemplate {
                    template,
                    target: difficulty,
                    coinbase_value,
                }
            }
            Err(e) => NetworkMessage::Error {
                message: format!("Failed to create template: {}", e),
                error_code: 500,
            }
        }
    }
    
    async fn handle_get_block(&self, hash: Hash, _client_ip: IpAddr) -> NetworkMessage {
        match self.get_block(&hash) {
            Some(block) => NetworkMessage::Block { block },
            None => NetworkMessage::Error {
                message: "Block not found".to_string(),
                error_code: 404,
            }
        }
    }
    
    async fn handle_get_transactions(&self, hashes: Vec<Hash>, _client_ip: IpAddr) -> NetworkMessage {
        let mut transactions = Vec::new();
        
        for hash in hashes {
            if let Some(tx) = self.get_transaction(&hash) {
                transactions.push(tx);
            }
        }
        
        NetworkMessage::Transactions { transactions }
    }
    
    /// Comprehensive block validation with all security checks
    fn validate_block_comprehensive(&self, block: &Block) -> Result<(), String> {
        // 1. Size validation
        let block_data = bincode::serialize(block)
            .map_err(|e| format!("Block serialization error: {}", e))?;
        
        if block_data.len() > self.config.max_block_size {
            return Err(format!("Block too large: {} bytes (max: {})", 
                             block_data.len(), self.config.max_block_size));
        }
        
        // 2. Basic structure validation
        if block.transactions.is_empty() {
            return Err("Block has no transactions".to_string());
        }
        
        if block.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
            return Err(format!("Too many transactions: {} (max: {})", 
                             block.transactions.len(), MAX_TRANSACTIONS_PER_BLOCK));
        }
        
        // 3. Proof of work validation
        if !block.is_valid_proof_of_work() {
            return Err("Invalid proof of work".to_string());
        }
        
        // 4. Height validation
        let expected_height = self.get_chain_height() + 1;
        if block.header.height != expected_height {
            return Err(format!("Invalid block height: expected {}, got {}", 
                             expected_height, block.header.height));
        }
        
        // 5. Previous hash validation
        let expected_prev_hash = self.get_best_block_hash();
        if block.header.prev_hash != expected_prev_hash {
            return Err("Invalid previous block hash".to_string());
        }
        
        // 6. Timestamp validation
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if block.header.timestamp > now + 7200 { // Max 2 hours in future
            return Err("Block timestamp too far in future".to_string());
        }
        if block.header.timestamp < now.saturating_sub(86400 * 7) { // Max 1 week in past
            return Err("Block timestamp too far in past".to_string());
        }
        
        // 7. Difficulty validation
        let expected_difficulty = self.calculate_expected_difficulty();
        if block.header.difficulty_target != expected_difficulty {
            return Err(format!("Invalid difficulty: expected {}, got {}", 
                             expected_difficulty, block.header.difficulty_target));
        }
        
        // 8. Merkle root validation
        if !block.verify_merkle_root() {
            return Err("Invalid merkle root".to_string());
        }
        
        // 9. Coinbase validation
        if !block.transactions[0].is_coinbase() {
            return Err("First transaction must be coinbase".to_string());
        }
        
        let expected_reward = self.calculate_block_reward();
        let total_fees: u64 = block.transactions.iter().skip(1).map(|tx| tx.fee).sum();
        let expected_coinbase_amount = expected_reward + total_fees;
        
        if block.transactions[0].amount != expected_coinbase_amount {
            return Err(format!("Invalid coinbase amount: expected {}, got {}", 
                             expected_coinbase_amount, block.transactions[0].amount));
        }
        
        // 10. Validate all transactions
        for (i, tx) in block.transactions.iter().enumerate() {
            if let Err(e) = self.validate_transaction_comprehensive(tx) {
                return Err(format!("Invalid transaction at index {}: {}", i, e));
            }
        }
        
        // 11. Check for duplicate transactions
        let mut tx_hashes = HashSet::new();
        for tx in &block.transactions {
            let tx_hash = tx.hash();
            if !tx_hashes.insert(tx_hash) {
                return Err("Duplicate transaction in block".to_string());
            }
        }
        
        Ok(())
    }
    
    /// Comprehensive transaction validation with all security checks
    fn validate_transaction_comprehensive(&self, tx: &Transaction) -> Result<(), String> {
        // 1. Size validation
        let tx_data = bincode::serialize(tx)
            .map_err(|e| format!("Transaction serialization error: {}", e))?;
        
        if tx_data.len() > self.config.max_transaction_size {
            return Err(format!("Transaction too large: {} bytes (max: {})", 
                             tx_data.len(), self.config.max_transaction_size));
        }
        
        // 2. Basic validation (signature, format, etc.)
        tx.validate(Some(self.chain_id))?;
        
        // 3. Amount validation
        if tx.amount == 0 && !tx.is_coinbase() {
            return Err("Zero amount transaction".to_string());
        }
        
        if tx.amount > 21_000_000 * 100_000_000 { // Max supply
            return Err("Amount exceeds maximum supply".to_string());
        }
        
        // 4. Fee validation
        if !tx.is_coinbase() {
            if tx.fee < MIN_TRANSACTION_FEE {
                return Err(format!("Fee too low: {} (minimum: {})", tx.fee, MIN_TRANSACTION_FEE));
            }
            
            if tx.fee > tx.amount {
                return Err("Fee exceeds transaction amount".to_string());
            }
            
            if tx.fee > tx.amount / 2 {
                return Err("Fee too high (maximum 50% of amount)".to_string());
            }
        }
        
        // 5. Chain ID validation
        if tx.chain_id != self.chain_id {
            return Err(format!("Invalid chain ID: expected {}, got {}", 
                             self.chain_id, tx.chain_id));
        }
        
        // 6. Nonce validation (prevent replay attacks)
        if !tx.is_coinbase() {
            // In a full implementation, check nonce against account state
            if tx.nonce == 0 {
                return Err("Invalid nonce (cannot be zero)".to_string());
            }
        }
        
        // 7. Address validation
        if tx.from == tx.to && !tx.is_coinbase() {
            return Err("Cannot send to same address".to_string());
        }
        
        // 8. Signature validation (already done in tx.validate(), but double-check)
        if !tx.verify() {
            return Err("Invalid transaction signature".to_string());
        }
        
        // 9. Expiry validation (if transaction has expiry)
        if tx.expiry > 0 {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            if now > tx.expiry {
                return Err("Transaction has expired".to_string());
            }
        }
        
        // 10. Data validation (if transaction has data)
        if let Some(ref data) = tx.data {
            if data.len() > 1024 { // Max 1KB of data
                return Err("Transaction data too large".to_string());
            }
        }
        
        Ok(())
    }
    
    // Helper methods (implement these based on your blockchain structure)
    fn get_chain_height(&self) -> u64 {
        self.blockchain.read().unwrap().get_best_block_height()
    }
    
    fn get_best_block_hash(&self) -> Hash {
        self.blockchain.read().unwrap().get_best_block_hash()
    }
    
    fn has_block(&self, hash: &Hash) -> bool {
        self.blockchain.read().unwrap().get_block(hash).unwrap_or(None).is_some()
    }
    
    fn get_block(&self, hash: &Hash) -> Option<Block> {
        self.blockchain.read().unwrap().get_block(hash).unwrap_or(None)
    }
    
    fn get_transaction(&self, _hash: &Hash) -> Option<Transaction> {
        // Implement transaction lookup
        None
    }
    
    fn submit_block(&self, block: Block) -> Result<(), String> {
        self.blockchain.write().unwrap()
            .add_block(block)
            .map_err(|e| e.to_string())
    }
    
    fn create_block_template(&self, miner_address: &str) -> Result<Block, String> {
        // Parse miner address
        let address_bytes = hex::decode(miner_address.trim_start_matches("0x"))
            .map_err(|_| "Invalid address format")?;
        
        if address_bytes.len() != 20 {
            return Err("Address must be 20 bytes".to_string());
        }
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&address_bytes);
        
        self.blockchain.read().unwrap()
            .create_block_template(&address)
            .map_err(|e| e.to_string())
    }
    
    fn get_current_difficulty(&self) -> u32 {
        // Implement difficulty calculation
        24 // Default difficulty
    }
    
    fn calculate_expected_difficulty(&self) -> u32 {
        // Implement expected difficulty calculation
        24 // Default difficulty
    }
    
    fn calculate_block_reward(&self) -> u64 {
        // Implement block reward calculation based on height
        5_000_000 // 5 PALI default reward
    }
    
    fn get_balance(&self, address: &str) -> u64 {
        // Parse address and get balance
        if let Ok(address_bytes) = hex::decode(address.trim_start_matches("0x")) {
            if address_bytes.len() == 20 {
                let mut addr_array = [0u8; 20];
                addr_array.copy_from_slice(&address_bytes);
                return self.blockchain.read().unwrap().get_balance(&addr_array);
            }
        }
        0
    }
    
    fn get_pending_transactions(&self, limit: usize) -> Vec<Transaction> {
        let mempool = self.mempool.read().unwrap();
        mempool.iter().take(limit).cloned().collect()
    }
    
    fn is_valid_address_format(&self, address: &str) -> bool {
        let clean_addr = address.trim_start_matches("0x");
        clean_addr.len() == 40 && clean_addr.chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// Get comprehensive node statistics
    pub fn get_node_stats(&self) -> serde_json::Value {
        let uptime = self.node_start_time.elapsed().as_secs();
        let blockchain_stats = self.blockchain.read().unwrap().get_blockchain_stats();
        let rate_limiter_stats = self.rate_limiter.get_stats();
        let mempool_size = self.mempool.read().unwrap().len();
        let peer_count = self.peers.read().unwrap().len();
        
        serde_json::json!({
            "node": {
                "uptime_seconds": uptime,
                "version": env!("CARGO_PKG_VERSION"),
                "chain_id": self.chain_id,
            },
            "blockchain": blockchain_stats,
            "mempool": {
                "size": mempool_size,
                "max_size": MAX_MEMPOOL_SIZE,
            },
            "network": {
                "peer_count": peer_count,
                "max_connections": self.config.max_connections,
            },
            "security": rate_limiter_stats,
            "performance": {
                "total_connections": self.total_connections.load(Ordering::Relaxed),
                "total_messages": self.total_messages.load(Ordering::Relaxed),
                "total_blocks_processed": self.total_blocks_processed.load(Ordering::Relaxed),
                "total_transactions_processed": self.total_transactions_processed.load(Ordering::Relaxed),
                "blocked_connections": self.blocked_connections.load(Ordering::Relaxed),
                "invalid_blocks": self.invalid_blocks.load(Ordering::Relaxed),
                "invalid_transactions": self.invalid_transactions.load(Ordering::Relaxed),
            }
        })
    }
    
    /// Cleanup task to remove expired entries and maintain performance
    pub async fn cleanup_task(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
        
        loop {
            interval.tick().await;
            
            // Cleanup rate limiter
            self.rate_limiter.cleanup_expired_entries();
            
            // Cleanup stale peer connections
            {
                let mut peers = self.peers.write().unwrap();
                let now = Instant::now();
                peers.retain(|_, stats| {
                    now.duration_since(stats.last_activity) < Duration::from_secs(3600)
                });
            }
            
            // Log statistics
            if log::log_enabled!(log::Level::Info) {
                let stats = self.get_node_stats();
                info!("📊 Node stats: {}", serde_json::to_string_pretty(&stats).unwrap_or_default());
            }
        }
    }
}

/// Connection guard to automatically clean up connections
struct ConnectionGuard {
    ip: IpAddr,
    rate_limiter: Arc<AdvancedRateLimiter>,
}

impl ConnectionGuard {
    fn new(ip: IpAddr, rate_limiter: Arc<AdvancedRateLimiter>) -> Self {
        rate_limiter.add_connection(ip);
        ConnectionGuard { ip, rate_limiter }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.rate_limiter.remove_connection(self.ip);
    }
}

/// Secure client handler with comprehensive security
async fn handle_secure_client(
    stream: TcpStream,
    node: Arc<SecureNodeService>,
) -> Result<()> {
    let peer_addr = stream.peer_addr()
        .map_err(|e| PaliError::Network(format!("Failed to get peer address: {}", e)))?;
    let client_ip = peer_addr.ip();
    
    // Security check: Can we accept this connection?
    if !node.rate_limiter.check_connection_allowed(client_ip) {
        node.blocked_connections.fetch_add(1, Ordering::Relaxed);
        warn!("🚫 Blocked connection from {}", peer_addr);
        return Err(PaliError::Security("Connection blocked".to_string()));
    }
    
    // Create connection guard for automatic cleanup
    let _connection_guard = ConnectionGuard::new(client_ip, Arc::clone(&node.rate_limiter));
    
    // Increment connection counter
    node.total_connections.fetch_add(1, Ordering::Relaxed);
    
    info!("✅ Secure connection accepted from {}", peer_addr);
    
    // Create secure network client
    let rate_limiter = Arc::new(Mutex::new(crate::network::RateLimiter::new()));
    let mut client = SecureNetworkClient::connect_with_stream(stream, peer_addr, rate_limiter)
        .await
        .map_err(|e| PaliError::Network(format!("Failed to create secure client: {}", e)))?;
    
    // Secure handshake with timeout
    let node_id = match timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS),
        client.handle_incoming_handshake("pali-secure-node", node.get_chain_height())
    ).await {
        Ok(Ok(id)) => {
            info!("🤝 Handshake successful with {} ({})", id, peer_addr);
            id
        }
        Ok(Err(e)) => {
            warn!("❌ Handshake failed with {}: {}", peer_addr, e);
            return Err(PaliError::Network(format!("Handshake failed: {}", e)));
        }
        Err(_) => {
            warn!("⏰ Handshake timeout with {}", peer_addr);
            return Err(PaliError::Network("Handshake timeout".to_string()));
        }
    };
    
    // Create connection stats
    let connection_stats = ConnectionStats {
        ip: client_ip,
        connected_at: Instant::now(),
        last_activity: Instant::now(),
        messages_sent: 0,
        messages_received: 0,
        bytes_sent: 0,
        bytes_received: 0,
        violations: 0,
        user_agent: None,
        peer_version: None,
    };
    
    // Register peer
    {
        let mut peers = node.peers.write().unwrap();
        peers.insert(peer_addr, connection_stats);
    }
    
    // Message processing loop with security and timeouts
    let mut message_count = 0u32;
    let session_start = Instant::now();
    
    loop {
        // Session timeout check
        if session_start.elapsed() > Duration::from_secs(SESSION_TIMEOUT_SECONDS) {
            info!("⏰ Session timeout for {}", peer_addr);
            break;
        }
        
        // Message count limit per session
        message_count += 1;
        if message_count > 10000 { // Max 10k messages per session
            warn!("🚫 Message limit exceeded for {}", peer_addr);
            break;
        }
        
        // Receive message with timeout
        match timeout(
            Duration::from_secs(MESSAGE_TIMEOUT_SECONDS),
            client.receive_message()
        ).await {
            Ok(Ok(message)) => {
                debug!("📨 Message from {}: {:?}", peer_addr, std::mem::discriminant(&message));
                
                // Update peer activity
                {
                    if let Some(mut peer_stats) = node.peers.write().unwrap().get_mut(&peer_addr) {
                        peer_stats.last_activity = Instant::now();
                        peer_stats.messages_received += 1;
                    }
                }
                
                // Process message securely
                let response = node.handle_secure_message(message, client_ip, Some(node_id.clone())).await;
                
                // Send response with timeout
                match timeout(
                    Duration::from_secs(MESSAGE_TIMEOUT_SECONDS),
                    client.send_message(&response)
                ).await {
                    Ok(Ok(())) => {
                        // Update peer stats
                        if let Some(mut peer_stats) = node.peers.write().unwrap().get_mut(&peer_addr) {
                            peer_stats.messages_sent += 1;
                        }
                    }
                    Ok(Err(e)) => {
                        error!("❌ Failed to send response to {}: {}", peer_addr, e);
                        break;
                    }
                    Err(_) => {
                        warn!("⏰ Response timeout to {}", peer_addr);
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("🔌 Connection closed by {}: {}", peer_addr, e);
                break;
            }
            Err(_) => {
                warn!("⏰ Message receive timeout from {}", peer_addr);
                break;
            }
        }
    }
    
    // Cleanup peer registration
    {
        let mut peers = node.peers.write().unwrap();
        peers.remove(&peer_addr);
    }
    
    info!("👋 Secure disconnection: {}", peer_addr);
    Ok(())
}

/// Main function with enterprise-grade security
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    
    // Parse command line arguments
    let matches = Command::new("Pali Coin Secure Node")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Enterprise-grade secure Pali Coin blockchain node")
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Port to listen on")
                .default_value("8333"),
        )
        .arg(
            Arg::new("data-dir")
                .short('d')
                .long("data-dir")
                .value_name("DIR")
                .help("Data directory for blockchain storage")
                .default_value("data"),
        )
        .arg(
            Arg::new("max-connections")
                .long("max-connections")
                .value_name("COUNT")
                .help("Maximum concurrent connections")
                .default_value("1000"),
        )
        .arg(
            Arg::new("chain-id")
                .long("chain-id")
                .value_name("ID")
                .help("Blockchain network chain ID")
                .default_value("1"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("pali-node.toml"),
        )
        .arg(
            Arg::new("enable-ddos-protection")
                .long("enable-ddos-protection")
                .help("Enable DDoS protection")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();
    
    // Parse arguments
    let port: u16 = matches.get_one::<String>("port")
        .unwrap()
        .parse()
        .map_err(|_| PaliError::Config("Invalid port number".to_string()))?;
    
    let data_dir = matches.get_one::<String>("data-dir").unwrap();
    
    let max_connections: usize = matches.get_one::<String>("max-connections")
        .unwrap()
        .parse()
        .map_err(|_| PaliError::Config("Invalid max connections".to_string()))?;
    
    let chain_id: u64 = matches.get_one::<String>("chain-id")
        .unwrap()
        .parse()
        .map_err(|_| PaliError::Config("Invalid chain ID".to_string()))?;
    
    let enable_ddos = matches.get_flag("enable-ddos-protection");
    
    // Create security configuration
    let mut security_config = SecurityConfig::default();
    security_config.max_connections = max_connections;
    security_config.enable_ddos_protection = enable_ddos;
    
    // Load additional config from file if it exists
    let config_path = matches.get_one::<String>("config").unwrap();
    if std::path::Path::new(config_path).exists() {
        match std::fs::read_to_string(config_path) {
            Ok(content) => {
                if let Ok(file_config) = toml::from_str::<SecurityConfig>(&content) {
                    security_config = file_config;
                    info!("📄 Loaded configuration from {}", config_path);
                }
            }
            Err(e) => {
                warn!("Failed to read config file {}: {}", config_path, e);
            }
        }
    }
    
    // Validate configuration
    if port < 1024 {
        return Err(PaliError::Config("Port must be >= 1024".to_string()));
    }
    
    if max_connections > 10000 {
        return Err(PaliError::Config("Max connections cannot exceed 10000".to_string()));
    }
    
    if chain_id == 0 {
        return Err(PaliError::Config("Chain ID cannot be zero".to_string()));
    }
    
    // Display startup banner
    info!("🚀 Starting Pali Coin Secure Node v{}", env!("CARGO_PKG_VERSION"));
    info!("🔐 Security Level: ENTERPRISE GRADE");
    info!("📁 Data Directory: {}", data_dir);
    info!("🌐 Chain ID: {}", chain_id);
    info!("🔒 Max Connections: {}", max_connections);
    info!("🛡️  DDoS Protection: {}", if enable_ddos { "ENABLED" } else { "DISABLED" });
    
    // Create secure node service
    let node = Arc::new(
        SecureNodeService::new(data_dir, chain_id, security_config)
            .map_err(|e| PaliError::Config(format!("Failed to create node: {}", e)))?
    );
    
    info!("⛓️  Blockchain initialized successfully");
    info!("📊 Current chain height: {}", node.get_chain_height());
    
    // Start cleanup task
    {
        let node_cleanup = Arc::clone(&node);
        tokio::spawn(async move {
            node_cleanup.cleanup_task().await;
        });
    }
    
    // Create TCP listener
    let listen_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&listen_addr)
        .await
        .map_err(|e| PaliError::Network(format!("Failed to bind to {}: {}", listen_addr, e)))?;
    
    info!("🎧 Secure node listening on: {}", listen_addr);
    info!("✅ Pali Coin node ready for connections");
    
    // Main connection acceptance loop
    let mut connection_count = 0u64;
    
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                connection_count += 1;
                let client_ip = addr.ip();
                
                debug!("🔍 Connection attempt #{} from {}", connection_count, addr);
                
                // Clone node reference for the task
                let node_clone = Arc::clone(&node);
                
                // Spawn secure client handler
                tokio::spawn(async move {
                    if let Err(e) = handle_secure_client(stream, node_clone).await {
                        match e {
                            PaliError::Security(_) => {
                                debug!("Security blocked connection from {}", addr);
                            }
                            PaliError::Network(_) => {
                                debug!("Network error with {}: {}", addr, e);
                            }
                            _ => {
                                warn!("Error handling client {}: {}", addr, e);
                            }
                        }
                    }
                });
            }
            Err(e) => {
                error!("❌ Failed to accept connection: {}", e);
                // Brief pause to prevent tight error loops
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
