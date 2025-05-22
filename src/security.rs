// src/security.rs - Bitcoin-grade security implementation
use crate::types::{Transaction, Block, Hash, Address};
use crate::error::{PaliError, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::sync::{Arc, RwLock, Mutex, atomic::{AtomicU64, AtomicBool, Ordering}};
use std::thread;
use log::{info, warn, error, debug};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher}};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use rand::{Rng, RngCore, thread_rng};
use secp256k1::{Secp256k1, Message, PublicKey, ecdsa::Signature};

// Security constants for enterprise-grade protection
const MAX_CONNECTIONS_PER_IP: usize = 10;
const MAX_REQUESTS_PER_MINUTE: usize = 60;
const BAN_DURATION: Duration = Duration::from_secs(3600); // 1 hour
const REPUTATION_DECAY_RATE: f64 = 0.01; // Daily decay
const MIN_REPUTATION_SCORE: i32 = -1000;
const MAX_REPUTATION_SCORE: i32 = 1000;
const CHALLENGE_DIFFICULTY: u32 = 4; // PoW challenge difficulty
const HONEYPOT_DETECTION_THRESHOLD: u32 = 5;
const INTRUSION_DETECTION_WINDOW: Duration = Duration::from_secs(300); // 5 minutes

/// Rate limiting configuration with advanced features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub fn decay_reputations(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.reputation_decay_timer) < Duration::from_secs(86400) {
            return; // Only decay once per day
        }
        
        for reputation in self.reputations.values_mut() {
            // Decay towards zero
            if reputation.score > 0 {
                reputation.score = (reputation.score as f64 * (1.0 - REPUTATION_DECAY_RATE)) as i32;
            } else if reputation.score < 0 {
                reputation.score = (reputation.score as f64 * (1.0 + REPUTATION_DECAY_RATE)) as i32;
            }
        }
        
        self.reputation_decay_timer = now;
        debug!("Reputation decay applied to {} peers", self.reputations.len());
    }
    
    pub fn cleanup_expired_bans(&mut self) {
        let now = Instant::now();
        let initial_count = self.banned_peers.len();
        
        self.banned_peers.retain(|_, ban_info| {
            now.duration_since(ban_info.banned_at) < ban_info.duration
        });
        
        let removed = initial_count - self.banned_peers.len();
        if removed > 0 {
            debug!("Removed {} expired bans", removed);
        }
    }
}

impl IntrusionDetection {
    pub fn new() -> Self {
        IntrusionDetection {
            suspicious_patterns: HashMap::new(),
            attack_signatures: Self::load_attack_signatures(),
            honeypot_addresses: Self::generate_honeypot_addresses(),
            geolocation_filter: None,
            anomaly_detector: AnomalyDetector::new(),
        }
    }
    
    pub fn track_connection(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let activity = self.suspicious_patterns.entry(ip).or_insert_with(|| SuspiciousActivity {
            rapid_connections: 0,
            invalid_messages: 0,
            scan_attempts: 0,
            first_activity: now,
            last_activity: now,
            pattern_score: 0.0,
        });
        
        // Check for rapid connections
        if now.duration_since(activity.last_activity) < Duration::from_secs(1) {
            activity.rapid_connections += 1;
            activity.pattern_score += 0.5;
        }
        
        activity.last_activity = now;
        
        // Flag suspicious activity
        if activity.rapid_connections > 10 {
            warn!("Rapid connections detected from {}: {}", ip, activity.rapid_connections);
        }
    }
    
    pub fn record_suspicious_activity(&mut self, ip: IpAddr, reason: &str) {
        let activity = self.suspicious_patterns.entry(ip).or_insert_with(|| SuspiciousActivity {
            rapid_connections: 0,
            invalid_messages: 0,
            scan_attempts: 0,
            first_activity: Instant::now(),
            last_activity: Instant::now(),
            pattern_score: 0.0,
        });
        
        match reason {
            "invalid_message" => {
                activity.invalid_messages += 1;
                activity.pattern_score += 1.0;
            }
            "scan_attempt" => {
                activity.scan_attempts += 1;
                activity.pattern_score += 2.0;
            }
            _ => {
                activity.pattern_score += 0.5;
            }
        }
        
        activity.last_activity = Instant::now();
        
        if activity.pattern_score > 10.0 {
            error!("High suspicious activity score for {}: {}", ip, activity.pattern_score);
        }
    }
    
    fn load_attack_signatures() -> Vec<AttackSignature> {
        vec![
            AttackSignature {
                name: "Buffer Overflow Attempt".to_string(),
                pattern: vec![0x41; 100], // AAAA...
                severity: 9,
                description: "Potential buffer overflow attack".to_string(),
            },
            AttackSignature {
                name: "SQL Injection".to_string(),
                pattern: b"' OR 1=1 --".to_vec(),
                severity: 8,
                description: "SQL injection attempt".to_string(),
            },
            AttackSignature {
                name: "XSS Attempt".to_string(),
                pattern: b"<script>".to_vec(),
                severity: 7,
                description: "Cross-site scripting attempt".to_string(),
            },
        ]
    }
    
    fn generate_honeypot_addresses() -> HashSet<Address> {
        let mut honeypots = HashSet::new();
        let mut rng = thread_rng();
        
        // Generate 100 honeypot addresses
        for _ in 0..100 {
            let mut addr = [0u8; 20];
            rng.fill(&mut addr);
            honeypots.insert(addr);
        }
        
        honeypots
    }
    
    pub fn is_honeypot_address(&self, address: &Address) -> bool {
        self.honeypot_addresses.contains(address)
    }
}

impl MessageSecurity {
    pub fn new() -> Self {
        MessageSecurity {
            spam_filter: SpamFilter::new(),
            content_validator: ContentValidator::new(),
            signature_cache: Arc::new(RwLock::new(HashMap::new())),
            nonce_tracker: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub fn validate_content(&self, message: &[u8]) -> Result<bool> {
        // Check message size
        if message.len() > self.content_validator.max_message_size {
            return Ok(false);
        }
        
        // Check for malformed data
        if self.content_validator.malformed_detection {
            if self.detect_malformed_data(message) {
                return Ok(false);
            }
        }
        
        // Check against attack signatures
        if self.contains_attack_signature(message) {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    pub fn is_spam(&self, ip: IpAddr, message: &[u8]) -> bool {
        self.spam_filter.is_spam(ip, message)
    }
    
    pub fn is_duplicate_transaction(&self, tx_hash: &Hash) -> bool {
        // Simple implementation - in production would use a more sophisticated cache
        let cache = self.signature_cache.read().unwrap();
        cache.contains_key(tx_hash)
    }
    
    pub fn validate_nonce(&self, address: &Address, nonce: u64) -> bool {
        let tracker = self.nonce_tracker.read().unwrap();
        if let Some(&last_nonce) = tracker.get(address) {
            nonce > last_nonce
        } else {
            true // First transaction from this address
        }
    }
    
    fn detect_malformed_data(&self, data: &[u8]) -> bool {
        // Check for null bytes in unexpected places
        if data.contains(&0x00) && data.len() < 32 {
            return true;
        }
        
        // Check for excessive repetition
        if data.len() > 10 {
            let first_byte = data[0];
            let same_bytes = data.iter().take_while(|&&b| b == first_byte).count();
            if same_bytes > data.len() / 2 {
                return true;
            }
        }
        
        false
    }
    
    fn contains_attack_signature(&self, data: &[u8]) -> bool {
        // Simple pattern matching - in production would use more sophisticated detection
        let dangerous_patterns = [
            b"../".as_slice(),
            b"<script>".as_slice(),
            b"javascript:".as_slice(),
            b"data:text/html".as_slice(),
        ];
        
        for pattern in &dangerous_patterns {
            if data.windows(pattern.len()).any(|window| window == *pattern) {
                return true;
            }
        }
        
        false
    }
}

impl SpamFilter {
    pub fn new() -> Self {
        SpamFilter {
            known_spam_hashes: HashSet::new(),
            suspicious_patterns: Vec::new(),
            frequency_limits: HashMap::new(),
        }
    }
    
    pub fn is_spam(&self, ip: IpAddr, message: &[u8]) -> bool {
        // Check hash-based spam detection
        let message_hash = {
            let mut hasher = Sha256::new();
            hasher.update(message);
            let hash_result = hasher.finalize();
            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(&hash_result);
            hash_array
        };
        
        if self.known_spam_hashes.contains(&message_hash) {
            return true;
        }
        
        // Check frequency limits
        if let Some(freq) = self.frequency_limits.get(&ip) {
            if freq.count > 100 && freq.last_reset.elapsed() < Duration::from_secs(60) {
                return true;
            }
        }
        
        // Check patterns
        for pattern in &self.suspicious_patterns {
            if self.matches_pattern(message, pattern) {
                return true;
            }
        }
        
        false
    }
    
    fn matches_pattern(&self, message: &[u8], pattern: &SpamPattern) -> bool {
        message.windows(pattern.pattern.len()).any(|window| window == pattern.pattern)
    }
}

impl ContentValidator {
    pub fn new() -> Self {
        let mut allowed_types = HashSet::new();
        allowed_types.insert("transaction".to_string());
        allowed_types.insert("block".to_string());
        allowed_types.insert("ping".to_string());
        allowed_types.insert("pong".to_string());
        
        ContentValidator {
            max_message_size: 1024 * 1024, // 1MB
            allowed_message_types: allowed_types,
            malformed_detection: true,
        }
    }
}

impl AnomalyDetector {
    pub fn new() -> Self {
        AnomalyDetector {
            baseline_metrics: HashMap::new(),
            current_metrics: HashMap::new(),
            threshold_multiplier: 3.0, // 3 standard deviations
        }
    }
    
    pub fn update_metric(&mut self, name: String, value: f64) {
        let metrics = self.current_metrics.entry(name).or_insert_with(VecDeque::new);
        metrics.push_back(value);
        
        // Keep only last 100 measurements
        if metrics.len() > 100 {
            metrics.pop_front();
        }
    }
    
    pub fn is_anomalous(&self, metric_name: &str, value: f64) -> bool {
        if let Some(baseline) = self.baseline_metrics.get(metric_name) {
            if let Some(current) = self.current_metrics.get(metric_name) {
                let mean = current.iter().sum::<f64>() / current.len() as f64;
                let variance = current.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / current.len() as f64;
                let std_dev = variance.sqrt();
                
                let threshold = baseline + (std_dev * self.threshold_multiplier);
                return value > threshold;
            }
        }
        
        false
    }
}

impl SecurityStats {
    pub fn new() -> Self {
        SecurityStats {
            connections_blocked: 0,
            requests_blocked: 0,
            spam_messages_blocked: 0,
            intrusion_attempts_detected: 0,
            reputation_updates: 0,
            bans_issued: 0,
            false_positives: 0,
            uptime: 0,
        }
    }
}

/// Helper function to double SHA-256 hash
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first_hash = Sha256::digest(data);
    let second_hash = Sha256::digest(&first_hash);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second_hash);
    result
}

/// Helper function to check if hash meets difficulty target
fn meets_difficulty_target(hash: &[u8; 32], target_bits: u32) -> bool {
    let mut count = 0u32;
    
    for byte in hash {
        if *byte == 0 {
            count += 8;
            continue;
        }
        
        let mut byte_val = *byte;
        while byte_val & 0x80 == 0 {
            count += 1;
            byte_val <<= 1;
        }
        break;
    }
    
    count >= target_bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_peer_reputation() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut reputation = PeerReputation::new(ip);
        
        reputation.update_score(10);
        assert_eq!(reputation.score, 10);
        
        reputation.update_score(-5);
        assert_eq!(reputation.score, 5);
        
        // Test clamping
        reputation.update_score(2000);
        assert_eq!(reputation.score, MAX_REPUTATION_SCORE);
    }
    
    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // Should allow initial connections
        for _ in 0..MAX_CONNECTIONS_PER_IP {
            assert!(limiter.allow_connection(ip));
        }
        
        // Should block after limit
        assert!(!limiter.allow_connection(ip));
    }
    
    #[test]
    fn test_security_manager() {
        let config = RateLimitConfig::default();
        let manager = SecurityManager::new(config);
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        
        // Should allow initial connection
        assert!(manager.check_connection(addr).unwrap());
        
        // Should allow request
        assert!(manager.check_request(addr, 1024).unwrap());
    }
    
    #[test]
    fn test_spam_detection() {
        let spam_filter = SpamFilter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let message = b"test message";
        
        // Should not detect spam for normal message
        assert!(!spam_filter.is_spam(ip, message));
    }
    
    #[test]
    fn test_intrusion_detection() {
        let mut ids = IntrusionDetection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        ids.track_connection(ip);
        ids.record_suspicious_activity(ip, "test_activity");
        
        assert!(ids.suspicious_patterns.contains_key(&ip));
    }
} max_connections_per_ip: usize,
    pub max_requests_per_minute: usize,
    pub max_bytes_per_minute: u64,
    pub max_new_connections_per_minute: usize,
    pub ban_duration_minutes: u64,
    pub whitelist_ips: Vec<IpAddr>,
    pub blacklist_ips: Vec<IpAddr>,
    pub enable_adaptive_limits: bool,
    pub burst_allowance: usize,
}

/// Peer reputation tracking system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    pub ip: IpAddr,
    pub score: i32,
    pub last_seen: u64,
    pub connection_count: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub bytes_transferred: u64,
    pub blocks_provided: u64,
    pub invalid_data_sent: u64,
    pub ban_count: u64,
    pub first_seen: u64,
    pub user_agent: Option<String>,
    pub protocol_violations: u64,
}

/// Intrusion detection and prevention system
#[derive(Debug)]
pub struct IntrusionDetection {
    suspicious_patterns: HashMap<IpAddr, SuspiciousActivity>,
    attack_signatures: Vec<AttackSignature>,
    honeypot_addresses: HashSet<Address>,
    geolocation_filter: Option<GeolocationFilter>,
    anomaly_detector: AnomalyDetector,
}

#[derive(Debug, Clone)]
pub struct SuspiciousActivity {
    pub rapid_connections: u32,
    pub invalid_messages: u32,
    pub scan_attempts: u32,
    pub first_activity: Instant,
    pub last_activity: Instant,
    pub pattern_score: f64,
}

#[derive(Debug, Clone)]
pub struct AttackSignature {
    pub name: String,
    pub pattern: Vec<u8>,
    pub severity: u8, // 1-10
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct GeolocationFilter {
    pub allowed_countries: HashSet<String>,
    pub blocked_countries: HashSet<String>,
    pub tor_exit_nodes: HashSet<IpAddr>,
}

#[derive(Debug)]
pub struct AnomalyDetector {
    baseline_metrics: HashMap<String, f64>,
    current_metrics: HashMap<String, VecDeque<f64>>,
    threshold_multiplier: f64,
}

/// Message security validation and filtering
#[derive(Debug)]
pub struct MessageSecurity {
    spam_filter: SpamFilter,
    content_validator: ContentValidator,
    signature_cache: Arc<RwLock<HashMap<Hash, bool>>>,
    nonce_tracker: Arc<RwLock<HashMap<Address, u64>>>,
}

#[derive(Debug)]
pub struct SpamFilter {
    known_spam_hashes: HashSet<Hash>,
    suspicious_patterns: Vec<SpamPattern>,
    frequency_limits: HashMap<IpAddr, MessageFrequency>,
}

#[derive(Debug, Clone)]
pub struct SpamPattern {
    pub pattern: Vec<u8>,
    pub confidence: f64,
    pub category: SpamCategory,
}

#[derive(Debug, Clone)]
pub enum SpamCategory {
    DuplicateContent,
    InvalidFormat,
    SuspiciousData,
    KnownAttack,
}

#[derive(Debug)]
pub struct MessageFrequency {
    pub count: u32,
    pub last_reset: Instant,
    pub burst_count: u32,
}

#[derive(Debug)]
pub struct ContentValidator {
    max_message_size: usize,
    allowed_message_types: HashSet<String>,
    malformed_detection: bool,
}

/// Main security manager coordinating all security features
pub struct SecurityManager {
    rate_limiter: Arc<RwLock<RateLimiter>>,
    reputation_system: Arc<RwLock<ReputationSystem>>,
    intrusion_detection: Arc<RwLock<IntrusionDetection>>,
    message_security: Arc<RwLock<MessageSecurity>>,
    config: RateLimitConfig,
    enabled: AtomicBool,
    stats: Arc<RwLock<SecurityStats>>,
}

#[derive(Debug)]
pub struct RateLimiter {
    connections: HashMap<IpAddr, ConnectionInfo>,
    requests: HashMap<IpAddr, RequestInfo>,
    global_stats: GlobalRateStats,
    adaptive_limits: HashMap<IpAddr, AdaptiveLimits>,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub count: usize,
    pub first_connection: Instant,
    pub last_connection: Instant,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub count: usize,
    pub last_reset: Instant,
    pub burst_tokens: i32,
    pub penalty_multiplier: f64,
}

#[derive(Debug)]
pub struct GlobalRateStats {
    pub total_connections: u64,
    pub total_requests: u64,
    pub total_bytes: u64,
    pub banned_ips: u64,
    pub start_time: Instant,
}

#[derive(Debug, Clone)]
pub struct AdaptiveLimits {
    pub current_limit: usize,
    pub base_limit: usize,
    pub adjustment_factor: f64,
    pub last_adjustment: Instant,
}

#[derive(Debug)]
pub struct ReputationSystem {
    reputations: HashMap<IpAddr, PeerReputation>,
    banned_peers: HashMap<IpAddr, BanInfo>,
    trusted_peers: HashSet<IpAddr>,
    reputation_decay_timer: Instant,
}

#[derive(Debug, Clone)]
pub struct BanInfo {
    pub reason: String,
    pub banned_at: Instant,
    pub duration: Duration,
    pub ban_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStats {
    pub connections_blocked: u64,
    pub requests_blocked: u64,
    pub spam_messages_blocked: u64,
    pub intrusion_attempts_detected: u64,
    pub reputation_updates: u64,
    pub bans_issued: u64,
    pub false_positives: u64,
    pub uptime: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            max_connections_per_ip: MAX_CONNECTIONS_PER_IP,
            max_requests_per_minute: MAX_REQUESTS_PER_MINUTE,
            max_bytes_per_minute: 1_000_000, // 1MB
            max_new_connections_per_minute: 20,
            ban_duration_minutes: 60,
            whitelist_ips: Vec::new(),
            blacklist_ips: Vec::new(),
            enable_adaptive_limits: true,
            burst_allowance: 10,
        }
    }
}

impl PeerReputation {
    pub fn new(ip: IpAddr) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        
        PeerReputation {
            ip,
            score: 0,
            last_seen: now,
            connection_count: 0,
            successful_requests: 0,
            failed_requests: 0,
            bytes_transferred: 0,
            blocks_provided: 0,
            invalid_data_sent: 0,
            ban_count: 0,
            first_seen: now,
            user_agent: None,
            protocol_violations: 0,
        }
    }
    
    pub fn update_score(&mut self, delta: i32) {
        self.score = (self.score + delta).clamp(MIN_REPUTATION_SCORE, MAX_REPUTATION_SCORE);
        self.last_seen = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    }
    
    pub fn is_trusted(&self) -> bool {
        self.score > 100 && self.ban_count == 0
    }
    
    pub fn is_suspicious(&self) -> bool {
        self.score < -50 || self.protocol_violations > 5
    }
    
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_requests + self.failed_requests;
        if total > 0 {
            self.successful_requests as f64 / total as f64
        } else {
            0.0
        }
    }
}

impl SecurityManager {
    pub fn new(config: RateLimitConfig) -> Self {
        SecurityManager {
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new())),
            reputation_system: Arc::new(RwLock::new(ReputationSystem::new())),
            intrusion_detection: Arc::new(RwLock::new(IntrusionDetection::new())),
            message_security: Arc::new(RwLock::new(MessageSecurity::new())),
            config,
            enabled: AtomicBool::new(true),
            stats: Arc::new(RwLock::new(SecurityStats::new())),
        }
    }
    
    pub fn start(&self) -> Result<()> {
        if self.enabled.load(Ordering::Relaxed) {
            return Err(PaliError::security("Security manager already running"));
        }
        
        self.enabled.store(true, Ordering::Relaxed);
        
        // Start background tasks
        self.start_reputation_decay_task();
        self.start_cleanup_task();
        self.start_monitoring_task();
        
        info!("🛡️  Security manager started");
        Ok(())
    }
    
    pub fn stop(&self) {
        self.enabled.store(false, Ordering::Relaxed);
        info!("🛑 Security manager stopped");
    }
    
    pub fn check_connection(&self, addr: SocketAddr) -> Result<bool> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(true);
        }
        
        let ip = addr.ip();
        
        // Check blacklist
        if self.config.blacklist_ips.contains(&ip) {
            debug!("Connection blocked: IP {} is blacklisted", ip);
            self.stats.write().unwrap().connections_blocked += 1;
            return Ok(false);
        }
        
        // Check whitelist (bypass other checks if whitelisted)
        if self.config.whitelist_ips.contains(&ip) {
            return Ok(true);
        }
        
        // Check if banned
        {
            let reputation_system = self.reputation_system.read().unwrap();
            if let Some(ban_info) = reputation_system.banned_peers.get(&ip) {
                if ban_info.banned_at.elapsed() < ban_info.duration {
                    debug!("Connection blocked: IP {} is banned for {:?}", ip, ban_info.reason);
                    self.stats.write().unwrap().connections_blocked += 1;
                    return Ok(false);
                }
            }
        }
        
        // Check rate limits
        {
            let mut rate_limiter = self.rate_limiter.write().unwrap();
            if !rate_limiter.allow_connection(ip) {
                debug!("Connection blocked: IP {} exceeded rate limits", ip);
                self.stats.write().unwrap().connections_blocked += 1;
                return Ok(false);
            }
        }
        
        // Check reputation
        {
            let reputation_system = self.reputation_system.read().unwrap();
            if let Some(reputation) = reputation_system.reputations.get(&ip) {
                if reputation.is_suspicious() {
                    warn!("Suspicious connection from IP {} (score: {})", ip, reputation.score);
                    // Don't block immediately, but flag for monitoring
                }
            }
        }
        
        // Update intrusion detection
        {
            let mut ids = self.intrusion_detection.write().unwrap();
            ids.track_connection(ip);
        }
        
        Ok(true)
    }
    
    pub fn check_request(&self, addr: SocketAddr, request_size: usize) -> Result<bool> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(true);
        }
        
        let ip = addr.ip();
        
        // Check rate limits
        {
            let mut rate_limiter = self.rate_limiter.write().unwrap();
            if !rate_limiter.allow_request(ip, request_size) {
                debug!("Request blocked: IP {} exceeded rate limits", ip);
                self.stats.write().unwrap().requests_blocked += 1;
                return Ok(false);
            }
        }
        
        // Update reputation for successful request
        {
            let mut reputation_system = self.reputation_system.write().unwrap();
            reputation_system.update_reputation(ip, 1, "successful_request");
        }
        
        Ok(true)
    }
    
    pub fn validate_message(&self, from: SocketAddr, message: &[u8]) -> Result<bool> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(true);
        }
        
        let ip = from.ip();
        
        // Check message security
        {
            let message_security = self.message_security.read().unwrap();
            if !message_security.validate_content(message)? {
                warn!("Invalid message content from IP {}", ip);
                self.stats.write().unwrap().spam_messages_blocked += 1;
                
                // Penalize reputation
                let mut reputation_system = self.reputation_system.write().unwrap();
                reputation_system.update_reputation(ip, -10, "invalid_message");
                
                return Ok(false);
            }
        }
        
        // Check for spam patterns
        {
            let message_security = self.message_security.read().unwrap();
            if message_security.is_spam(ip, message) {
                warn!("Spam message detected from IP {}", ip);
                self.stats.write().unwrap().spam_messages_blocked += 1;
                
                // Penalize reputation more severely for spam
                let mut reputation_system = self.reputation_system.write().unwrap();
                reputation_system.update_reputation(ip, -25, "spam_message");
                
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    pub fn validate_transaction(&self, from: SocketAddr, tx: &Transaction) -> Result<bool> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(true);
        }
        
        let ip = from.ip();
        
        // Basic transaction validation
        if let Err(e) = tx.validate(None) {
            warn!("Invalid transaction from IP {}: {}", ip, e);
            
            // Penalize reputation for invalid transactions
            let mut reputation_system = self.reputation_system.write().unwrap();
            reputation_system.update_reputation(ip, -20, "invalid_transaction");
            
            return Ok(false);
        }
        
        // Check for transaction spam (same transaction repeated)
        let tx_hash = tx.hash();
        {
            let message_security = self.message_security.read().unwrap();
            if message_security.is_duplicate_transaction(&tx_hash) {
                warn!("Duplicate transaction detected from IP {}", ip);
                
                let mut reputation_system = self.reputation_system.write().unwrap();
                reputation_system.update_reputation(ip, -15, "duplicate_transaction");
                
                return Ok(false);
            }
        }
        
        // Check nonce ordering (prevent replay attacks)
        {
            let message_security = self.message_security.read().unwrap();
            if !message_security.validate_nonce(&tx.from, tx.nonce) {
                warn!("Invalid nonce in transaction from IP {}", ip);
                
                let mut reputation_system = self.reputation_system.write().unwrap();
                reputation_system.update_reputation(ip, -30, "nonce_violation");
                
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    pub fn validate_block(&self, from: SocketAddr, block: &Block) -> Result<bool> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(true);
        }
        
        let ip = from.ip();
        
        // Basic block validation would be done by blockchain module
        // Here we focus on security-specific checks
        
        // Check if block is from a trusted source
        {
            let reputation_system = self.reputation_system.read().unwrap();
            if let Some(reputation) = reputation_system.reputations.get(&ip) {
                if reputation.is_trusted() {
                    // Fast-track validation for trusted peers
                    reputation_system.update_reputation_unlocked(ip, 5, "provided_block");
                    return Ok(true);
                }
            }
        }
        
        // Check proof of work
        if !block.is_valid_proof_of_work() {
            warn!("Invalid proof of work in block from IP {}", ip);
            
            let mut reputation_system = self.reputation_system.write().unwrap();
            reputation_system.update_reputation(ip, -50, "invalid_pow");
            
            return Ok(false);
        }
        
        // Update reputation for providing valid block
        {
            let mut reputation_system = self.reputation_system.write().unwrap();
            reputation_system.update_reputation(ip, 10, "valid_block");
        }
        
        Ok(true)
    }
    
    pub fn report_misbehavior(&self, addr: SocketAddr, reason: &str, severity: u8) {
        let ip = addr.ip();
        let penalty = -(severity as i32 * 10);
        
        warn!("Misbehavior reported for IP {}: {} (severity: {})", ip, reason, severity);
        
        {
            let mut reputation_system = self.reputation_system.write().unwrap();
            reputation_system.update_reputation(ip, penalty, reason);
            
            // Auto-ban for severe misbehavior
            if severity >= 8 {
                reputation_system.ban_peer(ip, BanInfo {
                    reason: reason.to_string(),
                    banned_at: Instant::now(),
                    duration: Duration::from_secs(self.config.ban_duration_minutes * 60),
                    ban_count: 1,
                });
            }
        }
        
        {
            let mut ids = self.intrusion_detection.write().unwrap();
            ids.record_suspicious_activity(ip, reason);
        }
    }
    
    pub fn generate_proof_of_work_challenge(&self, ip: IpAddr) -> (Vec<u8>, u32) {
        let mut challenge = vec![0u8; 32];
        thread_rng().fill_bytes(&mut challenge);
        
        // Include IP and timestamp to prevent reuse
        let mut hasher = Sha256::new();
        hasher.update(&challenge);
        hasher.update(&ip.to_string().as_bytes());
        hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().to_be_bytes());
        
        let final_challenge = hasher.finalize().to_vec();
        (final_challenge, CHALLENGE_DIFFICULTY)
    }
    
    pub fn verify_proof_of_work(&self, ip: IpAddr, challenge: &[u8], nonce: u64) -> bool {
        let mut data = Vec::new();
        data.extend_from_slice(challenge);
        data.extend_from_slice(&nonce.to_be_bytes());
        
        let hash = double_sha256(&data);
        meets_difficulty_target(&hash, CHALLENGE_DIFFICULTY)
    }
    
    pub fn get_stats(&self) -> SecurityStats {
        self.stats.read().unwrap().clone()
    }
    
    pub fn get_reputation(&self, ip: IpAddr) -> Option<PeerReputation> {
        self.reputation_system.read().unwrap().reputations.get(&ip).cloned()
    }
    
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let reputation_system = self.reputation_system.read().unwrap();
        if let Some(ban_info) = reputation_system.banned_peers.get(&ip) {
            ban_info.banned_at.elapsed() < ban_info.duration
        } else {
            false
        }
    }
    
    pub fn whitelist_ip(&mut self, ip: IpAddr) {
        self.config.whitelist_ips.push(ip);
        info!("IP {} added to whitelist", ip);
    }
    
    pub fn blacklist_ip(&mut self, ip: IpAddr) {
        self.config.blacklist_ips.push(ip);
        info!("IP {} added to blacklist", ip);
    }
    
    fn start_reputation_decay_task(&self) {
        let reputation_system = Arc::clone(&self.reputation_system);
        let enabled = Arc::clone(&self.enabled);
        
        thread::spawn(move || {
            while enabled.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(3600)); // Run every hour
                
                let mut system = reputation_system.write().unwrap();
                system.decay_reputations();
            }
        });
    }
    
    fn start_cleanup_task(&self) {
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let reputation_system = Arc::clone(&self.reputation_system);
        let enabled = Arc::clone(&self.enabled);
        
        thread::spawn(move || {
            while enabled.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(300)); // Run every 5 minutes
                
                {
                    let mut limiter = rate_limiter.write().unwrap();
                    limiter.cleanup_old_entries();
                }
                
                {
                    let mut system = reputation_system.write().unwrap();
                    system.cleanup_expired_bans();
                }
            }
        });
    }
    
    fn start_monitoring_task(&self) {
        let stats = Arc::clone(&self.stats);
        let enabled = Arc::clone(&self.enabled);
        
        thread::spawn(move || {
            let start_time = Instant::now();
            
            while enabled.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(60)); // Update every minute
                
                {
                    let mut stats = stats.write().unwrap();
                    stats.uptime = start_time.elapsed().as_secs();
                }
            }
        });
    }
}

// Implementation of helper structures
impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            connections: HashMap::new(),
            requests: HashMap::new(),
            global_stats: GlobalRateStats {
                total_connections: 0,
                total_requests: 0,
                total_bytes: 0,
                banned_ips: 0,
                start_time: Instant::now(),
            },
            adaptive_limits: HashMap::new(),
        }
    }
    
    pub fn allow_connection(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        
        let connection_info = self.connections.entry(ip).or_insert_with(|| ConnectionInfo {
            count: 0,
            first_connection: now,
            last_connection: now,
            total_bytes: 0,
        });
        
        // Check connection limit
        if connection_info.count >= MAX_CONNECTIONS_PER_IP {
            return false;
        }
        
        connection_info.count += 1;
        connection_info.last_connection = now;
        self.global_stats.total_connections += 1;
        
        true
    }
    
    pub fn allow_request(&mut self, ip: IpAddr, size: usize) -> bool {
        let now = Instant::now();
        
        let request_info = self.requests.entry(ip).or_insert_with(|| RequestInfo {
            count: 0,
            last_reset: now,
            burst_tokens: 10,
            penalty_multiplier: 1.0,
        });
        
        // Reset counter if a minute has passed
        if now.duration_since(request_info.last_reset) >= Duration::from_secs(60) {
            request_info.count = 0;
            request_info.last_reset = now;
            request_info.burst_tokens = 10;
        }
        
        // Check rate limit
        let effective_limit = (MAX_REQUESTS_PER_MINUTE as f64 / request_info.penalty_multiplier) as usize;
        if request_info.count >= effective_limit && request_info.burst_tokens <= 0 {
            return false;
        }
        
        if request_info.count >= effective_limit {
            request_info.burst_tokens -= 1;
        }
        
        request_info.count += 1;
        self.global_stats.total_requests += 1;
        self.global_stats.total_bytes += size as u64;
        
        true
    }
    
    pub fn cleanup_old_entries(&mut self) {
        let now = Instant::now();
        let cleanup_threshold = Duration::from_secs(3600); // 1 hour
        
        self.connections.retain(|_, info| {
            now.duration_since(info.last_connection) < cleanup_threshold
        });
        
        self.requests.retain(|_, info| {
            now.duration_since(info.last_reset) < cleanup_threshold
        });
    }
}

impl ReputationSystem {
    pub fn new() -> Self {
        ReputationSystem {
            reputations: HashMap::new(),
            banned_peers: HashMap::new(),
            trusted_peers: HashSet::new(),
            reputation_decay_timer: Instant::now(),
        }
    }
    
    pub fn update_reputation(&mut self, ip: IpAddr, delta: i32, reason: &str) {
        let reputation = self.reputations.entry(ip).or_insert_with(|| PeerReputation::new(ip));
        reputation.update_score(delta);
        
        debug!("Updated reputation for {}: {} ({})", ip, delta, reason);
        
        // Auto-trust high reputation peers
        if reputation.score > 500 {
            self.trusted_peers.insert(ip);
        }
    }
    
    pub fn update_reputation_unlocked(&self, ip: IpAddr, delta: i32, reason: &str) {
        // This would need to be implemented differently in a real system
        // For now, just log the action
        debug!("Would update reputation for {}: {} ({})", ip, delta, reason);
    }
    
    pub fn ban_peer(&mut self, ip: IpAddr, ban_info: BanInfo) {
        self.banned_peers.insert(ip, ban_info);
        self.trusted_peers.remove(&ip);
        
        if let Some(reputation) = self.reputations.get_mut(&ip) {
            reputation.ban_count += 1;
            reputation.score = MIN_REPUTATION_SCORE;
        }
        
        warn!("Banned peer {}", ip);
    }
    
    pub
