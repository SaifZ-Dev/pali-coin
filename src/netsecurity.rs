use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use sha2::{Sha256, Digest};
use rand::Rng;
use serde::{Serialize, Deserialize};

// Peer reputation scoring
#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub addr: IpAddr,
    pub score: i32,              // Reputation score, negative is bad
    pub last_activity: Instant,  // Time of last activity
    pub last_misbehavior: Option<Instant>, // Time of last misbehavior
    pub banned_until: Option<Instant>, // Ban expiration time
    pub connection_failures: u32,  // Number of consecutive connection failures
    pub successful_connections: u32, // Number of successful connections
    pub blocks_provided: u32,    // Number of valid blocks provided
    pub transactions_provided: u32, // Number of valid transactions provided
    pub invalid_blocks: u32,     // Number of invalid blocks provided
    pub invalid_transactions: u32, // Number of invalid transactions provided
}

// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_connections_per_ip: u32,
    pub max_connections_per_subnet: u32,
    pub max_messages_per_minute: u32,
    pub max_bytes_per_minute: u64,
    pub max_blocks_per_minute: u32,
    pub max_txs_per_minute: u32,
}

// DDoS protection manager
#[derive(Debug)]
pub struct DDoSProtection {
    pub rate_limits: RateLimitConfig,
    pub peer_reputations: Arc<Mutex<HashMap<IpAddr, PeerReputation>>>,
    pub banned_ips: Arc<Mutex<HashSet<IpAddr>>>,
    pub connection_counts: Arc<Mutex<HashMap<IpAddr, u32>>>,
    pub subnet_counts: Arc<Mutex<HashMap<String, u32>>>,
    pub message_counts: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
    pub byte_counts: Arc<Mutex<HashMap<IpAddr, (u64, Instant)>>>,
    pub challenge_tokens: Arc<Mutex<HashMap<IpAddr, String>>>,
}

impl PeerReputation {
    pub fn new(addr: IpAddr) -> Self {
        PeerReputation {
            addr,
            score: 0,
            last_activity: Instant::now(),
            last_misbehavior: None,
            banned_until: None,
            connection_failures: 0,
            successful_connections: 0,
            blocks_provided: 0,
            transactions_provided: 0,
            invalid_blocks: 0,
            invalid_transactions: 0,
        }
    }
    
    pub fn is_banned(&self) -> bool {
        if let Some(banned_until) = self.banned_until {
            return banned_until > Instant::now();
        }
        false
    }
    
    pub fn record_successful_connection(&mut self) {
        self.successful_connections += 1;
        self.connection_failures = 0;
        self.score += 1;
        self.last_activity = Instant::now();
    }
    
    pub fn record_connection_failure(&mut self) {
        self.connection_failures += 1;
        if self.connection_failures > 5 {
            self.score -= 2;
        }
    }
    
    pub fn record_valid_block(&mut self) {
        self.blocks_provided += 1;
        self.score += 10;
        self.last_activity = Instant::now();
    }
    
    pub fn record_valid_transaction(&mut self) {
        self.transactions_provided += 1;
        self.score += 1;
        self.last_activity = Instant::now();
    }
    
    pub fn record_invalid_block(&mut self) {
        self.invalid_blocks += 1;
        self.score -= 20;
        self.last_misbehavior = Some(Instant::now());
        self.last_activity = Instant::now();
        
        // Ban peer temporarily for providing invalid blocks
        if self.invalid_blocks > 2 {
            self.banned_until = Some(Instant::now() + Duration::from_secs(86400)); // 24 hours
        }
    }
    
    pub fn record_invalid_transaction(&mut self) {
        self.invalid_transactions += 1;
        self.score -= 5;
        self.last_misbehavior = Some(Instant::now());
        self.last_activity = Instant::now();
        
        // Ban peer temporarily for providing too many invalid transactions
        if self.invalid_transactions > 10 {
            self.banned_until = Some(Instant::now() + Duration::from_secs(3600)); // 1 hour
        }
    }
}

impl DDoSProtection {
    pub fn new(rate_limits: RateLimitConfig) -> Self {
        DDoSProtection {
            rate_limits,
            peer_reputations: Arc::new(Mutex::new(HashMap::new())),
            banned_ips: Arc::new(Mutex::new(HashSet::new())),
            connection_counts: Arc::new(Mutex::new(HashMap::new())),
            subnet_counts: Arc::new(Mutex::new(HashMap::new())),
            message_counts: Arc::new(Mutex::new(HashMap::new())),
            byte_counts: Arc::new(Mutex::new(HashMap::new())),
            challenge_tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    // Check if a new connection is allowed
    pub fn allow_connection(&self, ip: IpAddr) -> bool {
        // Check if IP is banned
        if self.banned_ips.lock().unwrap().contains(&ip) {
            return false;
        }
        
        // Check peer reputation
        if let Some(rep) = self.peer_reputations.lock().unwrap().get(&ip) {
            if rep.is_banned() {
                return false;
            }
        }
        
        // Check per-IP connection limit
        let mut connections = self.connection_counts.lock().unwrap();
        let conn_count = connections.entry(ip).or_insert(0);
        if *conn_count >= self.rate_limits.max_connections_per_ip {
            return false;
        }
        
        // Check per-subnet connection limit (for IPv4)
        if let IpAddr::V4(ipv4) = ip {
            let subnet = format!("{}.{}.{}.0/24", ipv4.octets()[0], ipv4.octets()[1], ipv4.octets()[2]);
            let mut subnets = self.subnet_counts.lock().unwrap();
            let subnet_count = subnets.entry(subnet).or_insert(0);
            if *subnet_count >= self.rate_limits.max_connections_per_subnet {
                return false;
            }
            *subnet_count += 1;
        }
        
        // Update connection count
        *conn_count += 1;
        
        // Generate a challenge token for proof of work
        let mut rng = rand::thread_rng();
        let token: String = (0..32).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect();
        self.challenge_tokens.lock().unwrap().insert(ip, token.clone());
        
        true
    }
    
    // Verify proof of work from client
    pub fn verify_proof_of_work(&self, ip: IpAddr, nonce: &str) -> bool {
        let token = match self.challenge_tokens.lock().unwrap().get(&ip) {
            Some(t) => t.clone(),
            None => return false,
        };
        
        // Calculate expected hash
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.update(nonce.as_bytes());
        let hash = hasher.finalize();
        
        // Check if the hash meets our difficulty requirement (e.g., 4 leading zeros)
        hash[0] == 0 && hash[1] == 0 && (hash[2] & 0xF0) == 0
    }
    
    // Track message rate
    pub fn allow_message(&self, ip: IpAddr, size: usize) -> bool {
        // Check if IP is banned
        if self.banned_ips.lock().unwrap().contains(&ip) {
            return false;
        }
        
        // Check message rate
        let now = Instant::now();
        let mut message_counts = self.message_counts.lock().unwrap();
        let (count, timestamp) = message_counts.entry(ip).or_insert((0, now));
        
        // Reset counter if a minute has passed
        if now.duration_since(*timestamp).as_secs() > 60 {
            *count = 0;
            *timestamp = now;
        }
        
        if *count >= self.rate_limits.max_messages_per_minute {
            // Record misbehavior
            if let Some(rep) = self.peer_reputations.lock().unwrap().get_mut(&ip) {
                rep.score -= 1;
                rep.last_misbehavior = Some(now);
            }
            return false;
        }
        
        *count += 1;
        
        // Check byte rate
        let mut byte_counts = self.byte_counts.lock().unwrap();
        let (bytes, byte_timestamp) = byte_counts.entry(ip).or_insert((0, now));
        
        // Reset counter if a minute has passed
        if now.duration_since(*byte_timestamp).as_secs() > 60 {
            *bytes = 0;
            *byte_timestamp = now;
        }
        
        if *bytes + size as u64 > self.rate_limits.max_bytes_per_minute {
            // Record misbehavior
            if let Some(rep) = self.peer_reputations.lock().unwrap().get_mut(&ip) {
                rep.score -= 1;
                rep.last_misbehavior = Some(now);
            }
            return false;
        }
        
        *bytes += size as u64;
        
        true
    }
    
    // Implement Eclipse attack prevention by ensuring diverse peer connections
    pub fn ensure_diverse_peers(&self, current_peers: &HashMap<IpAddr, String>) -> Vec<IpAddr> {
        let mut subnets = HashMap::new();
        let mut asn_distribution = HashMap::new();
        let mut country_distribution = HashMap::new();
        
        // Analyze current peer distribution
        for (ip,_metadata) in current_peers {
            if let IpAddr::V4(ipv4) = ip {
                // Track /16 subnets
                let subnet = format!("{}.{}.0.0/16", ipv4.octets()[0], ipv4.octets()[1]);
                *subnets.entry(subnet).or_insert(0) += 1;
            }
            
            // In a real implementation, we would parse metadata for ASN and country
            // For this example, we'll just use placeholders
            let asn = "AS12345"; // This would come from metadata
            let country = "US";   // This would come from metadata
            
            *asn_distribution.entry(asn.to_string()).or_insert(0) += 1;
            *country_distribution.entry(country.to_string()).or_insert(0) += 1;
        }
        
        // Identify peers to disconnect based on overrepresentation
        let mut peers_to_disconnect = Vec::new();
        
        // Ensure no single subnet has more than 10% of connections
        let total_peers = current_peers.len();
        let max_subnet_peers = (total_peers as f64 * 0.1).ceil() as usize;
        
        for (subnet, count) in subnets {
            if count > max_subnet_peers {
                // Find peers in this subnet to disconnect
                for (ip, _) in current_peers {
                    if let IpAddr::V4(ipv4) = ip {
                        let peer_subnet = format!("{}.{}.0.0/16", ipv4.octets()[0], ipv4.octets()[1]);
                        if peer_subnet == subnet && peers_to_disconnect.len() < (count - max_subnet_peers) {
                            peers_to_disconnect.push(*ip);
                        }
                    }
                }
            }
        }
        
        peers_to_disconnect
    }
}
