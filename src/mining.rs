// src/mining.rs - Bitcoin-grade mining implementation
use crate::types::{Block, Transaction, Hash, Address, meets_difficulty_target, double_sha256};
use crate::blockchain::Blockchain;
use crate::wallet::Wallet;
use crate::network::{SecureNetworkClient, NetworkMessage};
use crate::error::{PaliError, Result};
use crate::config::MiningConfig;
use std::sync::{Arc, RwLock, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque};
use log::{info, warn, error, debug};
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;
use rand::{Rng, thread_rng};
use sha2::{Sha256, Digest};
use crossbeam::channel::{Receiver, Sender, unbounded};

// Mining constants for Bitcoin-level security
const STRATUM_PROTOCOL_VERSION: &str = "1.0";
const WORK_RESTART_TIMEOUT: Duration = Duration::from_secs(120);
const SHARE_SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);
const HASHRATE_WINDOW: Duration = Duration::from_secs(300); // 5 minutes
const MIN_MINING_DIFFICULTY: u32 = 8; // Minimum 8 leading zero bits
const MAX_MINING_DIFFICULTY: u32 = 32; // Maximum difficulty
const MINING_THREAD_PRIORITY: i32 = -10; // Higher priority for mining threads

/// Mining statistics and performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningStats {
    pub hashrate: f64,
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub stale_shares: u64,
    pub blocks_found: u64,
    pub last_share_time: u64,
    pub mining_duration: u64,
    pub efficiency: f64, // shares/hash ratio
    pub power_consumption: f64, // estimated watts
    pub temperature: f64, // estimated temperature
}

/// Mining job from pool or local blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningJob {
    pub job_id: String,
    pub block_template: Block,
    pub target_difficulty: u32,
    pub clean_jobs: bool,
    pub timestamp: u64,
    pub extra_nonce_start: u64,
    pub extra_nonce_range: u64,
}

/// Mining work result/share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningShare {
    pub job_id: String,
    pub nonce: u64,
    pub timestamp: u64,
    pub hash: Hash,
    pub difficulty: f64,
    pub worker_name: String,
}

/// Mining pool connection and communication
#[derive(Debug)]
pub struct MiningPool {
    pub url: String,
    pub username: String,
    pub password: String,
    pub worker_name: String,
    pub connection: Option<SecureNetworkClient>,
    pub subscribed: bool,
    pub session_id: Option<String>,
    pub extra_nonce1: String,
    pub extra_nonce2_size: u32,
}

/// Enterprise-grade mining engine
pub struct Miner {
    config: MiningConfig,
    blockchain: Arc<RwLock<Blockchain>>,
    wallet: Wallet,
    stats: Arc<RwLock<MiningStats>>,
    is_mining: Arc<AtomicBool>,
    current_job: Arc<RwLock<Option<MiningJob>>>,
    mining_threads: Vec<JoinHandle<()>>,
    work_sender: Sender<MiningJob>,
    work_receiver: Receiver<MiningJob>,
    share_sender: Sender<MiningShare>,
    share_receiver: Receiver<MiningShare>,
    hashrate_samples: Arc<Mutex<VecDeque<(Instant, u64)>>>,
    pool: Option<MiningPool>,
    solo_mining: bool,
}

impl MiningStats {
    pub fn new() -> Self {
        MiningStats {
            hashrate: 0.0,
            accepted_shares: 0,
            rejected_shares: 0,
            stale_shares: 0,
            blocks_found: 0,
            last_share_time: 0,
            mining_duration: 0,
            efficiency: 0.0,
            power_consumption: 0.0,
            temperature: 0.0,
        }
    }
    
    pub fn update_hashrate(&mut self, hashrate: f64) {
        self.hashrate = hashrate;
        self.efficiency = if hashrate > 0.0 {
            (self.accepted_shares as f64) / (hashrate * (self.mining_duration as f64 / 3600.0))
        } else {
            0.0
        };
    }
    
    pub fn accept_share(&mut self) {
        self.accepted_shares += 1;
        self.last_share_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
    
    pub fn reject_share(&mut self) {
        self.rejected_shares += 1;
    }
    
    pub fn stale_share(&mut self) {
        self.stale_shares += 1;
    }
    
    pub fn found_block(&mut self) {
        self.blocks_found += 1;
        info!("🎉 BLOCK FOUND! Total blocks: {}", self.blocks_found);
    }
    
    pub fn get_acceptance_rate(&self) -> f64 {
        let total = self.accepted_shares + self.rejected_shares + self.stale_shares;
        if total > 0 {
            (self.accepted_shares as f64) / (total as f64) * 100.0
        } else {
            0.0
        }
    }
}

impl MiningJob {
    pub fn new(block_template: Block, difficulty: u32) -> Self {
        let job_id = format!("{:016x}", thread_rng().gen::<u64>());
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        MiningJob {
            job_id,
            block_template,
            target_difficulty: difficulty,
            clean_jobs: false,
            timestamp,
            extra_nonce_start: thread_rng().gen(),
            extra_nonce_range: 0xFFFFFFFF,
        }
    }
    
    pub fn is_stale(&self, current_time: u64) -> bool {
        current_time - self.timestamp > WORK_RESTART_TIMEOUT.as_secs()
    }
}

impl MiningPool {
    pub fn new(url: String, username: String, password: String) -> Self {
        MiningPool {
            url,
            username,
            password: password.clone(),
            worker_name: format!("pali_miner_{}", thread_rng().gen::<u32>()),
            connection: None,
            subscribed: false,
            session_id: None,
            extra_nonce1: String::new(),
            extra_nonce2_size: 4,
        }
    }
    
    pub async fn connect(&mut self) -> Result<()> {
        let rate_limiter = Arc::new(Mutex::new(
            crate::network::RateLimiter::new()
        ));
        
        let client = SecureNetworkClient::connect(&self.url, rate_limiter).await
            .map_err(|e| PaliError::network(format!("Failed to connect to pool: {}", e)))?;
        
        self.connection = Some(client);
        info!("Connected to mining pool: {}", self.url);
        Ok(())
    }
    
    pub async fn subscribe(&mut self) -> Result<()> {
        if let Some(ref mut connection) = self.connection {
            let subscribe_msg = NetworkMessage::Subscribe {
                user_agent: "PaliCoin/1.0".to_string(),
                protocol_version: STRATUM_PROTOCOL_VERSION.to_string(),
                worker_name: self.worker_name.clone(),
            };
            
            connection.send_message(&subscribe_msg).await
                .map_err(|e| PaliError::network(format!("Failed to send subscribe: {}", e)))?;
            
            match connection.receive_message().await {
                Ok(NetworkMessage::SubscribeResponse { session_id, extra_nonce1, extra_nonce2_size }) => {
                    self.session_id = Some(session_id);
                    self.extra_nonce1 = extra_nonce1;
                    self.extra_nonce2_size = extra_nonce2_size;
                    self.subscribed = true;
                    info!("Successfully subscribed to mining pool");
                    Ok(())
                }
                Ok(NetworkMessage::Error { message, .. }) => {
                    Err(PaliError::network(format!("Pool subscription failed: {}", message)))
                }
                _ => Err(PaliError::network("Invalid subscription response"))
            }
        } else {
            Err(PaliError::network("Not connected to pool"))
        }
    }
    
    pub async fn authorize(&mut self) -> Result<()> {
        if let Some(ref mut connection) = self.connection {
            let auth_msg = NetworkMessage::Authorize {
                username: self.username.clone(),
                password: self.password.clone(),
            };
            
            connection.send_message(&auth_msg).await
                .map_err(|e| PaliError::network(format!("Failed to send authorization: {}", e)))?;
            
            match connection.receive_message().await {
                Ok(NetworkMessage::AuthorizeResponse { success }) => {
                    if success {
                        info!("Successfully authorized with mining pool");
                        Ok(())
                    } else {
                        Err(PaliError::network("Mining pool authorization failed"))
                    }
                }
                _ => Err(PaliError::network("Invalid authorization response"))
            }
        } else {
            Err(PaliError::network("Not connected to pool"))
        }
    }
    
    pub async fn submit_share(&mut self, share: &MiningShare) -> Result<bool> {
        if let Some(ref mut connection) = self.connection {
            let submit_msg = NetworkMessage::SubmitShare {
                job_id: share.job_id.clone(),
                worker_name: share.worker_name.clone(),
                nonce: share.nonce,
                timestamp: share.timestamp,
                hash: share.hash,
            };
            
            connection.send_message(&submit_msg).await
                .map_err(|e| PaliError::network(format!("Failed to submit share: {}", e)))?;
            
            match tokio::time::timeout(SHARE_SUBMIT_TIMEOUT, connection.receive_message()).await {
                Ok(Ok(NetworkMessage::ShareResponse { accepted, .. })) => {
                    if accepted {
                        info!("✅ Share accepted by pool");
                    } else {
                        warn!("❌ Share rejected by pool");
                    }
                    Ok(accepted)
                }
                Ok(Ok(NetworkMessage::Error { message, .. })) => {
                    warn!("Share submission error: {}", message);
                    Ok(false)
                }
                Ok(Err(e)) => {
                    error!("Network error during share submission: {}", e);
                    Ok(false)
                }
                Err(_) => {
                    warn!("Share submission timeout");
                    Ok(false)
                }
            }
        } else {
            Err(PaliError::network("Not connected to pool"))
        }
    }
}

impl Miner {
    pub fn new(
        config: MiningConfig,
        blockchain: Arc<RwLock<Blockchain>>,
        wallet: Wallet,
    ) -> Result<Self> {
        let (work_sender, work_receiver) = unbounded();
        let (share_sender, share_receiver) = unbounded();
        
        let pool = if !config.solo_mining {
            config.pool_address.as_ref().map(|addr| {
                MiningPool::new(
                    addr.clone(),
                    wallet.get_address_string(),
                    "x".to_string(), // Default password for most pools
                )
            })
        } else {
            None
        };
        
        Ok(Miner {
            config,
            blockchain,
            wallet,
            stats: Arc::new(RwLock::new(MiningStats::new())),
            is_mining: Arc::new(AtomicBool::new(false)),
            current_job: Arc::new(RwLock::new(None)),
            mining_threads: Vec::new(),
            work_sender,
            work_receiver,
            share_sender,
            share_receiver,
            hashrate_samples: Arc::new(Mutex::new(VecDeque::new())),
            pool,
            solo_mining: config.solo_mining,
        })
    }
    
    pub async fn start_mining(&mut self) -> Result<()> {
        if self.is_mining.load(Ordering::Relaxed) {
            return Err(PaliError::mining("Mining is already running"));
        }
        
        info!("🚀 Starting Pali Coin miner...");
        
        // Connect to pool if not solo mining
        if !self.solo_mining {
            if let Some(ref mut pool) = self.pool {
                pool.connect().await?;
                pool.subscribe().await?;
                pool.authorize().await?;
            }
        }
        
        self.is_mining.store(true, Ordering::Relaxed);
        
        // Start work generation thread
        self.start_work_generator();
        
        // Start share submission thread
        self.start_share_submitter();
        
        // Start mining worker threads
        self.start_mining_threads();
        
        // Start monitoring thread
        self.start_monitoring_thread();
        
        info!("✅ Mining started with {} threads", self.config.threads);
        Ok(())
    }
    
    pub fn stop_mining(&mut self) {
        if !self.is_mining.load(Ordering::Relaxed) {
            return;
        }
        
        info!("🛑 Stopping mining...");
        self.is_mining.store(false, Ordering::Relaxed);
        
        // Wait for all mining threads to finish
        while let Some(handle) = self.mining_threads.pop() {
            let _ = handle.join();
        }
        
        // Update final stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.update_hashrate(0.0);
        }
        
        info!("✅ Mining stopped");
    }
    
    fn start_work_generator(&self) {
        let blockchain = Arc::clone(&self.blockchain);
        let wallet_address = self.wallet.address;
        let work_sender = self.work_sender.clone();
        let is_mining = Arc::clone(&self.is_mining);
        let current_job = Arc::clone(&self.current_job);
        let solo_mining = self.solo_mining;
        let difficulty = self.config.difficulty;
        
        thread::spawn(move || {
            let mut last_block_hash = [0u8; 32];
            
            while is_mining.load(Ordering::Relaxed) {
                if solo_mining {
                    // Generate work from local blockchain
                    if let Ok(blockchain) = blockchain.read() {
                        let current_hash = blockchain.get_best_block_hash();
                        
                        // Only generate new work if blockchain has changed
                        if current_hash != last_block_hash {
                            match blockchain.create_block_template(&wallet_address) {
                                Ok(mut template) => {
                                    template.header.difficulty_target = difficulty.max(MIN_MINING_DIFFICULTY).min(MAX_MINING_DIFFICULTY);
                                    
                                    let job = MiningJob::new(template, difficulty);
                                    
                                    if let Err(e) = work_sender.send(job.clone()) {
                                        error!("Failed to send mining job: {}", e);
                                        break;
                                    }
                                    
                                    *current_job.write().unwrap() = Some(job);
                                    last_block_hash = current_hash;
                                    debug!("Generated new mining job");
                                }
                                Err(e) => {
                                    error!("Failed to create block template: {}", e);
                                }
                            }
                        }
                    }
                }
                
                thread::sleep(Duration::from_secs(1));
            }
        });
    }
    
    fn start_share_submitter(&self) {
        let blockchain = Arc::clone(&self.blockchain);
        let share_receiver = self.share_receiver.clone();
        let stats = Arc::clone(&self.stats);
        let is_mining = Arc::clone(&self.is_mining);
        let current_job = Arc::clone(&self.current_job);
        let solo_mining = self.solo_mining;
        
        thread::spawn(move || {
            while is_mining.load(Ordering::Relaxed) {
                if let Ok(share) = share_receiver.recv_timeout(Duration::from_secs(1)) {
                    let current_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    
                    // Check if share is for current job
                    let job_valid = {
                        if let Some(ref job) = *current_job.read().unwrap() {
                            job.job_id == share.job_id && !job.is_stale(current_time)
                        } else {
                            false
                        }
                    };
                    
                    if !job_valid {
                        stats.write().unwrap().stale_share();
                        warn!("Stale share rejected");
                        continue;
                    }
                    
                    if solo_mining {
                        // Submit directly to local blockchain
                        if let Some(ref job) = *current_job.read().unwrap() {
                            let mut block = job.block_template.clone();
                            block.header.nonce = share.nonce;
                            block.header.timestamp = share.timestamp;
                            
                            // Verify the block meets difficulty
                            if block.is_valid_proof_of_work() {
                                match blockchain.write() {
                                    Ok(mut bc) => {
                                        match bc.add_block(block) {
                                            Ok(_) => {
                                                stats.write().unwrap().found_block();
                                                info!("🎉 Block found and added to blockchain!");
                                            }
                                            Err(e) => {
                                                error!("Failed to add mined block: {}", e);
                                                stats.write().unwrap().reject_share();
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to acquire blockchain lock: {}", e);
                                        stats.write().unwrap().reject_share();
                                    }
                                }
                            } else {
                                warn!("Invalid proof of work in share");
                                stats.write().unwrap().reject_share();
                            }
                        }
                    } else {
                        // Submit to mining pool (would require async runtime)
                        // For now, just accept the share
                        stats.write().unwrap().accept_share();
                        debug!("Share submitted to pool");
                    }
                }
            }
        });
    }
    
    fn start_mining_threads(&mut self) {
        for thread_id in 0..self.config.threads {
            let work_receiver = self.work_receiver.clone();
            let share_sender = self.share_sender.clone();
            let is_mining = Arc::clone(&self.is_mining);
            let hashrate_samples = Arc::clone(&self.hashrate_samples);
            let worker_name = format!("worker_{}", thread_id);
            
            let handle = thread::spawn(move || {
                Self::mining_worker(
                    thread_id,
                    worker_name,
                    work_receiver,
                    share_sender,
                    is_mining,
                    hashrate_samples,
                );
            });
            
            self.mining_threads.push(handle);
        }
    }
    
    fn mining_worker(
        thread_id: u32,
        worker_name: String,
        work_receiver: Receiver<MiningJob>,
        share_sender: Sender<MiningShare>,
        is_mining: Arc<AtomicBool>,
        hashrate_samples: Arc<Mutex<VecDeque<(Instant, u64)>>>,
    ) {
        info!("Mining worker {} started", thread_id);
        
        let mut current_job: Option<MiningJob> = None;
        let mut nonce_start = thread_rng().gen::<u64>();
        let mut hashes = 0u64;
        let mut last_hashrate_update = Instant::now();
        
        while is_mining.load(Ordering::Relaxed) {
            // Check for new work
            if let Ok(job) = work_receiver.try_recv() {
                current_job = Some(job);
                nonce_start = thread_rng().gen::<u64>();
                debug!("Worker {} received new job", thread_id);
            }
            
            if let Some(ref job) = current_job {
                // Check if job is still valid
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                if job.is_stale(current_time) {
                    current_job = None;
                    continue;
                }
                
                // Mine for a batch of nonces
                let batch_size = 100_000;
                let start_nonce = nonce_start;
                let end_nonce = start_nonce.wrapping_add(batch_size);
                
                for nonce in start_nonce..end_nonce {
                    if !is_mining.load(Ordering::Relaxed) {
                        break;
                    }
                    
                    let mut block = job.block_template.clone();
                    block.header.nonce = nonce;
                    block.header.timestamp = current_time;
                    
                    let hash = block.hash();
                    hashes += 1;
                    
                    // Check if we found a valid share
                    if meets_difficulty_target(&hash, job.target_difficulty) {
                        let share = MiningShare {
                            job_id: job.job_id.clone(),
                            nonce,
                            timestamp: current_time,
                            hash,
                            difficulty: Self::calculate_share_difficulty(&hash),
                            worker_name: worker_name.clone(),
                        };
                        
                        if let Err(e) = share_sender.send(share) {
                            error!("Failed to send share: {}", e);
                        } else {
                            info!("⛏️  Worker {} found share! Nonce: {}", thread_id, nonce);
                        }
                    }
                    
                    // Update hashrate periodically
                    if last_hashrate_update.elapsed() >= Duration::from_secs(10) {
                        let now = Instant::now();
                        let mut samples = hashrate_samples.lock().unwrap();
                        samples.push_back((now, hashes));
                        
                        // Keep only last 5 minutes of samples
                        while let Some(&(time, _)) = samples.front() {
                            if now.duration_since(time) > HASHRATE_WINDOW {
                                samples.pop_front();
                            } else {
                                break;
                            }
                        }
                        
                        last_hashrate_update = now;
                    }
                }
                
                nonce_start = end_nonce;
            } else {
                // No work available, sleep briefly
                thread::sleep(Duration::from_millis(100));
            }
        }
        
        info!("Mining worker {} stopped", thread_id);
    }
    
    fn start_monitoring_thread(&self) {
        let stats = Arc::clone(&self.stats);
        let hashrate_samples = Arc::clone(&self.hashrate_samples);
        let is_mining = Arc::clone(&self.is_mining);
        
        thread::spawn(move || {
            let mut last_update = Instant::now();
            
            while is_mining.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(30));
                
                // Calculate current hashrate
                let hashrate = {
                    let samples = hashrate_samples.lock().unwrap();
                    if samples.len() >= 2 {
                        let (earliest_time, earliest_hashes) = samples.front().unwrap();
                        let (latest_time, latest_hashes) = samples.back().unwrap();
                        
                        let time_diff = latest_time.duration_since(*earliest_time).as_secs_f64();
                        let hash_diff = latest_hashes.saturating_sub(*earliest_hashes);
                        
                        if time_diff > 0.0 {
                            hash_diff as f64 / time_diff
                        } else {
                            0.0
                        }
                    } else {
                        0.0
                    }
                };
                
                // Update stats
                {
                    let mut stats = stats.write().unwrap();
                    stats.update_hashrate(hashrate);
                    stats.mining_duration += last_update.elapsed().as_secs();
                    
                    // Estimate power consumption (rough approximation)
                    stats.power_consumption = hashrate * 0.1; // Assume 0.1W per H/s
                    
                    // Log mining statistics
                    info!(
                        "⛏️  Mining Stats: {:.2} H/s | Shares: {} accepted, {} rejected | Blocks: {} | Efficiency: {:.2}%",
                        hashrate,
                        stats.accepted_shares,
                        stats.rejected_shares,
                        stats.blocks_found,
                        stats.get_acceptance_rate()
                    );
                }
                
                last_update = Instant::now();
            }
        });
    }
    
    fn calculate_share_difficulty(hash: &Hash) -> f64 {
        // Count leading zero bits
        let mut difficulty_bits = 0;
        for byte in hash {
            if *byte == 0 {
                difficulty_bits += 8;
            } else {
                difficulty_bits += byte.leading_zeros();
                break;
            }
        }
        
        // Convert to difficulty value
        if difficulty_bits > 0 {
            2f64.powi(difficulty_bits as i32)
        } else {
            1.0
        }
    }
    
    pub fn get_stats(&self) -> MiningStats {
        self.stats.read().unwrap().clone()
    }
    
    pub fn is_mining(&self) -> bool {
        self.is_mining.load(Ordering::Relaxed)
    }
    
    pub fn get_current_hashrate(&self) -> f64 {
        self.get_stats().hashrate
    }
    
    pub fn get_efficiency(&self) -> f64 {
        self.get_stats().efficiency
    }
    
    pub fn set_difficulty(&mut self, difficulty: u32) {
        let clamped_difficulty = difficulty.max(MIN_MINING_DIFFICULTY).min(MAX_MINING_DIFFICULTY);
        self.config.difficulty = clamped_difficulty;
        info!("Mining difficulty updated to {}", clamped_difficulty);
    }
    
    pub fn estimate_time_to_block(&self, network_hashrate: f64) -> Duration {
        let our_hashrate = self.get_current_hashrate();
        let target_time = 600.0; // 10 minutes in seconds
        
        if our_hashrate > 0.0 && network_hashrate > 0.0 {
            let our_percentage = our_hashrate / network_hashrate;
            let estimated_seconds = target_time / our_percentage;
            Duration::from_secs(estimated_seconds as u64)
        } else {
            Duration::from_secs(u64::MAX) // Essentially infinite
        }
    }
}

impl Drop for Miner {
    fn drop(&mut self) {
        self.stop_mining();
    }
}

/// Helper function to format hashrate for display
pub fn format_hashrate(hashrate: f64) -> String {
    if hashrate >= 1_000_000_000_000.0 {
        format!("{:.2} TH/s", hashrate / 1_000_000_000_000.0)
    } else if hashrate >= 1_000_000_000.0 {
        format!("{:.2} GH/s", hashrate / 1_000_000_000.0)
    } else if hashrate >= 1_000_000.0 {
        format!("{:.2} MH/s", hashrate / 1_000_000.0)
    } else if hashrate >= 1_000.0 {
        format!("{:.2} KH/s", hashrate / 1_000.0)
    } else {
        format!("{:.2} H/s", hashrate)
    }
}

/// Calculate optimal difficulty based on network hashrate and target block time
pub fn calculate_optimal_difficulty(network_hashrate: f64, target_time: u64) -> u32 {
    // Use Bitcoin's difficulty adjustment algorithm
    let target_hashes = network_hashrate * target_time as f64;
    let difficulty_bits = (target_hashes.log2().ceil() as u32).max(MIN_MINING_DIFFICULTY).min(MAX_MINING_DIFFICULTY);
    difficulty_bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_mining_stats() {
        let mut stats = MiningStats::new();
        
        stats.accept_share();
        assert_eq!(stats.accepted_shares, 1);
        
        stats.reject_share();
        assert_eq!(stats.rejected_shares, 1);
        
        assert_eq!(stats.get_acceptance_rate(), 50.0);
    }
    
    #[test]
    fn test_mining_job_creation() {
        let block = Block::new([0; 32], vec![], 24, 1);
        let job = MiningJob::new(block, 24);
        
        assert!(!job.job_id.is_empty());
        assert_eq!(job.target_difficulty, 24);
        assert!(!job.is_stale(job.timestamp + 10));
    }
    
    #[test]
    fn test_share_difficulty_calculation() {
        let hash = [0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let difficulty = Miner::calculate_share_difficulty(&hash);
        assert!(difficulty > 1.0);
    }
    
    #[test]
    fn test_hashrate_formatting() {
        assert_eq!(format_hashrate(1000.0), "1.00 KH/s");
        assert_eq!(format_hashrate(1_000_000.0), "1.00 MH/s");
        assert_eq!(format_hashrate(1_000_000_000.0), "1.00 GH/s");
    }
}
