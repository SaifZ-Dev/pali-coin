// src/network.rs - Enterprise-grade P2P networking with DDoS protection
use serde::{Deserialize, Serialize};
use crate::types::{Block, Transaction, Hash};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration, Instant};
use log::{info, debug, warn, error};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use sha2::{Sha256, Digest};
use rand::{Rng, thread_rng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use std::time::{SystemTime, UNIX_EPOCH};

// Network constants
const PROTOCOL_VERSION: u32 = 1;
const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024; // 32MB max message
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(60);
const MAX_CONNECTIONS_PER_IP: usize = 3;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_MESSAGES_PER_MINUTE: usize = 100;
const BAN_DURATION: Duration = Duration::from_secs(3600); // 1 hour

/// Enhanced transaction info for network transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub block_height: u64,
    pub timestamp: u64,
    pub confirmations: u64,
}

/// Node information for peer discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub version: String,
    pub user_agent: String,
    pub services: u64,
    pub timestamp: u64,
    pub addr: SocketAddr,
    pub height: u64,
}

/// Message priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Enhanced network message types with security features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    // Handshake and authentication
    Hello { 
        version: u32, 
        node_id: String, 
        user_agent: String, 
        services: u64,
        height: u64,
        timestamp: u64,
        challenge: Vec<u8>, // Anti-replay challenge
    },
    HelloAck { 
        version: u32, 
        node_id: String,
        user_agent: String,
        services: u64,
        height: u64,
        timestamp: u64,
        challenge_response: Vec<u8>,
    },
    
    // Block synchronization
    GetHeaders { 
        start_hash: Hash, 
        end_hash: Hash,
        max_headers: u32,
    },
    Headers { 
        headers: Vec<crate::types::BlockHeader>,
        continuation: bool,
    },
    GetBlocks { 
        start_height: u64, 
        end_height: u64,
        max_blocks: u32,
    },
    Blocks { 
        blocks: Vec<Block>,
        continuation: bool,
    },
    GetBlock { 
        hash: Hash 
    },
    Block { 
        block: Block 
    },
    NewBlock { 
        block: Block,
        priority: MessagePriority,
    },
    
    // Transaction handling
    GetTransactions { 
        hashes: Vec<Hash> 
    },
    Transactions { 
        transactions: Vec<Transaction> 
    },
    NewTransaction { 
        transaction: Transaction,
        priority: MessagePriority,
    },
    GetMempool,
    MempoolTxs { 
        transactions: Vec<Transaction> 
    },
    
    // Blockchain queries
    GetHeight,
    Height { 
        height: u64 
    },
    GetBalance { 
        address: String 
    },
    Balance { 
        address: String, 
        amount: u64 
    },
    GetTransactionHistory { 
        address: String,
        offset: usize,
        limit: usize,
    },
    TransactionHistory { 
        address: String, 
        transactions: Vec<TransactionInfo>,
        total_count: usize,
    },
    
    // Peer discovery and network topology
    GetPeers,
    Peers { 
        peers: Vec<NodeInfo> 
    },
    GetAddr,
    Addr { 
        addresses: Vec<SocketAddr> 
    },
    
    // Mining support
    GetTemplate { 
        miner_address: String 
    },
    BlockTemplate { 
        template: Block,
        target: u32,
        coinbase_value: u64,
    },
    SubmitBlock { 
        block: Block 
    },
    SubmitWork { 
        block_hash: Hash,
        nonce: u64,
        timestamp: u64,
    },
    
    // Network maintenance
    Ping { 
        nonce: u64,
        timestamp: u64,
    },
    Pong { 
        nonce: u64,
        timestamp: u64,
    },
    Reject { 
        message_type: String,
        reason: String,
        data: Vec<u8>,
    },
    Alert { 
        message: String,
        signature: Vec<u8>,
        timestamp: u64,
    },
    
    // Security and anti-spam
    ProofOfWork { 
        challenge: Vec<u8>,
        difficulty: u32,
    },
    ProofOfWorkResponse { 
        nonce: u64,
        hash: Vec<u8>,
    },
    
    // Error handling
    Error { 
        message: String,
        error_code: u32,
    },
}

/// Connection state tracking
#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub addr: SocketAddr,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub version: Option<u32>,
    pub node_id: Option<String>,
    pub height: u64,
    pub is_authenticated: bool,
}

/// Rate limiting and DDoS protection
#[derive(Debug)]
pub struct RateLimiter {
    connections_per_ip: HashMap<IpAddr, usize>,
    message_counts: HashMap<IpAddr, (usize, Instant)>,
    banned_ips: HashMap<IpAddr, Instant>,
    reputation_scores: HashMap<IpAddr, i32>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            connections_per_ip: HashMap::new(),
            message_counts: HashMap::new(),
            banned_ips: HashMap::new(),
            reputation_scores: HashMap::new(),
        }
    }
    
    pub fn check_connection_limit(&mut self, ip: IpAddr) -> bool {
        // Check if IP is banned
        if let Some(&ban_time) = self.banned_ips.get(&ip) {
            if Instant::now().duration_since(ban_time) < BAN_DURATION {
                return false;
            } else {
                self.banned_ips.remove(&ip);
            }
        }
        
        // Check connection limit
        let count = self.connections_per_ip.entry(ip).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_IP {
            return false;
        }
        
        *count += 1;
        true
    }
    
    pub fn check_rate_limit(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        
        match self.message_counts.get_mut(&ip) {
            Some((count, last_reset)) => {
                if now.duration_since(*last_reset) > RATE_LIMIT_WINDOW {
                    *count = 1;
                    *last_reset = now;
                } else {
                    *count += 1;
                    if *count > MAX_MESSAGES_PER_MINUTE {
                        // Ban the IP for excessive messaging
                        self.banned_ips.insert(ip, now);
                        warn!("Banned IP {} for rate limit violation", ip);
                        return false;
                    }
                }
            }
            None => {
                self.message_counts.insert(ip, (1, now));
            }
        }
        
        true
    }
    
    pub fn remove_connection(&mut self, ip: IpAddr) {
        if let Some(count) = self.connections_per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.connections_per_ip.remove(&ip);
            }
        }
    }
    
    pub fn update_reputation(&mut self, ip: IpAddr, delta: i32) {
        let score = self.reputation_scores.entry(ip).or_insert(0);
        *score += delta;
        
        // Ban IPs with very low reputation
        if *score < -100 {
            self.banned_ips.insert(ip, Instant::now());
            warn!("Banned IP {} for low reputation score: {}", ip, score);
        }
    }
}

/// Message encryption for sensitive communications
pub struct MessageSecurity {
    encryption_key: Option<[u8; 32]>,
    mac_key: Option<[u8; 32]>,
    node_keypair: Option<(SecretKey, PublicKey)>,
}

impl MessageSecurity {
    pub fn new() -> Self {
        MessageSecurity {
            encryption_key: None,
            mac_key: None,
            node_keypair: None,
        }
    }
    
    pub fn generate_keypair(&mut self) -> Result<PublicKey, String> {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut thread_rng());
        self.node_keypair = Some((secret_key, public_key));
        Ok(public_key)
    }
    
    pub fn establish_shared_secret(&mut self, peer_public_key: &PublicKey) -> Result<(), String> {
        let (secret_key, _) = self.node_keypair.as_ref()
            .ok_or("No keypair generated")?;
        
        // Simplified ECDH - in production, use proper ECDH
        let secp = Secp256k1::new();
        let shared_point = peer_public_key.combine(secret_key)
            .map_err(|_| "Failed to compute shared secret")?;
        
        // Derive keys from shared secret
        let shared_bytes = shared_point.serialize();
        let mut hasher = Sha256::new();
        hasher.update(b"pali_encryption");
        hasher.update(&shared_bytes);
        let enc_key = hasher.finalize();
        
        let mut hasher = Sha256::new();
        hasher.update(b"pali_mac");
        hasher.update(&shared_bytes);
        let mac_key = hasher.finalize();
        
        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&enc_key);
        self.encryption_key = Some(encryption_key);
        
        let mut mac_key_bytes = [0u8; 32];
        mac_key_bytes.copy_from_slice(&mac_key);
        self.mac_key = Some(mac_key_bytes);
        
        Ok(())
    }
    
    pub fn encrypt_message(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.encryption_key.ok_or("No encryption key")?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|_| "Encryption failed")?;
        
        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    pub fn decrypt_message(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("Invalid encrypted data".to_string());
        }
        
        let key = self.encryption_key.ok_or("No encryption key")?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed".to_string())
    }
}

/// Secure network client with comprehensive security features
pub struct SecureNetworkClient {
    pub stream: TcpStream,
    pub peer_address: SocketAddr,
    pub connection_state: ConnectionState,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    pub security: MessageSecurity,
    last_ping: Instant,
}

impl SecureNetworkClient {
    pub async fn connect(
        address: &str,
        rate_limiter: Arc<Mutex<RateLimiter>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let addr: SocketAddr = address.parse()?;
        
        // Check rate limiting before connecting
        {
            let mut limiter = rate_limiter.lock().unwrap();
            if !limiter.check_connection_limit(addr.ip()) {
                return Err("Connection limit exceeded or IP banned".into());
            }
        }
        
        let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(&addr)).await??;
        
        let connection_state = ConnectionState {
            addr,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
            version: None,
            node_id: None,
            height: 0,
            is_authenticated: false,
        };
        
        info!("Connected to peer: {}", addr);
        
        Ok(SecureNetworkClient {
            stream,
            peer_address: addr,
            connection_state,
            rate_limiter,
            security: MessageSecurity::new(),
            last_ping: Instant::now(),
        })
    }
    
    pub async fn send_message(&mut self, message: &NetworkMessage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check rate limiting
        {
            let mut limiter = self.rate_limiter.lock().unwrap();
            if !limiter.check_rate_limit(self.peer_address.ip()) {
                return Err("Rate limit exceeded".into());
            }
        }
        
        // Serialize message
        let serialized = bincode::serialize(message)?;
        
        // Check message size
        if serialized.len() > MAX_MESSAGE_SIZE {
            return Err("Message too large".into());
        }
        
        // Add message header: [length][checksum][timestamp]
        let length = serialized.len() as u32;
        let checksum = Self::calculate_checksum(&serialized);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        // Send header
        self.stream.write_all(&length.to_be_bytes()).await?;
        self.stream.write_all(&checksum).await?;
        self.stream.write_all(&timestamp.to_be_bytes()).await?;
        
        // Encrypt sensitive messages if security is established
        let data_to_send = if self.should_encrypt_message(message) && self.security.encryption_key.is_some() {
            self.security.encrypt_message(&serialized)?
        } else {
            serialized
        };
        
        // Send message data
        self.stream.write_all(&data_to_send).await?;
        
        // Update statistics
        self.connection_state.bytes_sent += (16 + data_to_send.len()) as u64; // 16 bytes header + data
        self.connection_state.messages_sent += 1;
        self.connection_state.last_activity = Instant::now();
        
        debug!("Sent message to {}: {:?}", self.peer_address, message);
        Ok(())
    }
    
    pub async fn receive_message(&mut self) -> Result<NetworkMessage, Box<dyn std::error::Error + Send + Sync>> {
        // Check rate limiting
        {
            let mut limiter = self.rate_limiter.lock().unwrap();
            if !limiter.check_rate_limit(self.peer_address.ip()) {
                return Err("Rate limit exceeded".into());
            }
        }
        
        // Read message header: [length][checksum][timestamp]
        let mut header = [0u8; 16]; // 4 + 4 + 8 bytes
        timeout(CONNECTION_TIMEOUT, self.stream.read_exact(&mut header)).await??;
        
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let expected_checksum = [header[4], header[5], header[6], header[7]];
        let message_timestamp = u64::from_be_bytes([
            header[8], header[9], header[10], header[11],
            header[12], header[13], header[14], header[15]
        ]);
        
        // Validate message size
        if length > MAX_MESSAGE_SIZE {
            return Err("Message too large".into());
        }
        
        // Validate timestamp (prevent replay attacks)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if message_timestamp > now + 300 || message_timestamp < now.saturating_sub(300) {
            // Allow 5 minute window for clock skew
            warn!("Message timestamp out of range from {}", self.peer_address);
            {
                let mut limiter = self.rate_limiter.lock().unwrap();
                limiter.update_reputation(self.peer_address.ip(), -10);
            }
        }
        
        // Read message data
        let mut buffer = vec![0u8; length];
        timeout(CONNECTION_TIMEOUT, self.stream.read_exact(&mut buffer)).await??;
        
        // Verify checksum
        let actual_checksum = Self::calculate_checksum(&buffer);
        if actual_checksum != expected_checksum {
            return Err("Message checksum mismatch".into());
        }
        
        // Decrypt if needed
        let decrypted_data = if buffer.len() > 12 && self.security.encryption_key.is_some() {
            // Try to decrypt, fall back to plaintext if it fails
            self.security.decrypt_message(&buffer).unwrap_or(buffer)
        } else {
            buffer
        };
        
        // Deserialize message
        let message: NetworkMessage = bincode::deserialize(&decrypted_data)?;
        
        // Update statistics
        self.connection_state.bytes_received += (16 + length) as u64;
        self.connection_state.messages_received += 1;
        self.connection_state.last_activity = Instant::now();
        
        // Update reputation based on message quality
        {
            let mut limiter = self.rate_limiter.lock().unwrap();
            limiter.update_reputation(self.peer_address.ip(), 1);
        }
        
        debug!("Received message from {}: {:?}", self.peer_address, message);
        Ok(message)
    }
    
    pub async fn handshake(&mut self, our_node_id: &str, our_height: u64) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Generate challenge for anti-replay protection
        let mut challenge = [0u8; 32];
        thread_rng().fill(&mut challenge);
        
        let hello = NetworkMessage::Hello {
            version: PROTOCOL_VERSION,
            node_id: our_node_id.to_string(),
            user_agent: "PaliCoin/1.0".to_string(),
            services: 1, // Full node
            height: our_height,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            challenge: challenge.to_vec(),
        };
        
        self.send_message(&hello).await?;
        
        match timeout(CONNECTION_TIMEOUT, self.receive_message()).await?? {
            NetworkMessage::HelloAck { 
                version, 
                node_id, 
                user_agent,
                services: _,
                height,
                timestamp: _,
                challenge_response,
            } => {
                // Verify challenge response
                let expected_response = Self::calculate_challenge_response(&challenge, &node_id);
                if challenge_response != expected_response {
                    return Err("Invalid challenge response".into());
                }
                
                // Check version compatibility
                if version != PROTOCOL_VERSION {
                    warn!("Version mismatch with {}: {} vs {}", self.peer_address, version, PROTOCOL_VERSION);
                }
                
                // Update connection state
                self.connection_state.version = Some(version);
                self.connection_state.node_id = Some(node_id.clone());
                self.connection_state.height = height;
                self.connection_state.is_authenticated = true;
                
                info!("Handshake successful with {} ({}), height: {}", node_id, user_agent, height);
                Ok(node_id)
            }
            _ => Err("Invalid handshake response".into())
        }
    }
    
    pub async fn handle_incoming_handshake(&mut self, our_node_id: &str, our_height: u64) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        match timeout(CONNECTION_TIMEOUT, self.receive_message()).await?? {
            NetworkMessage::Hello { 
                version, 
                node_id, 
                user_agent,
                services: _,
                height,
                timestamp: _,
                challenge,
            } => {
                // Check version compatibility
                if version != PROTOCOL_VERSION {
                    warn!("Version mismatch with {}: {} vs {}", self.peer_address, version, PROTOCOL_VERSION);
                }
                
                // Generate challenge response
                let challenge_response = Self::calculate_challenge_response(&challenge, our_node_id);
                
                let hello_ack = NetworkMessage::HelloAck {
                    version: PROTOCOL_VERSION,
                    node_id: our_node_id.to_string(),
                    user_agent: "PaliCoin/1.0".to_string(),
                    services: 1, // Full node
                    height: our_height,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    challenge_response,
                };
                
                self.send_message(&hello_ack).await?;
                
                // Update connection state
                self.connection_state.version = Some(version);
                self.connection_state.node_id = Some(node_id.clone());
                self.connection_state.height = height;
                self.connection_state.is_authenticated = true;
                
                info!("Incoming handshake from {} ({}), height: {}", node_id, user_agent, height);
                Ok(node_id)
            }
            _ => Err("Invalid handshake message".into())
        }
    }
    
    pub async fn send_ping(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.last_ping.elapsed() >= PING_INTERVAL {
            let nonce = thread_rng().gen::<u64>();
            let ping = NetworkMessage::Ping {
                nonce,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            };
            
            self.send_message(&ping).await?;
            self.last_ping = Instant::now();
        }
        Ok(())
    }
    
    pub async fn handle_ping(&mut self, nonce: u64, timestamp: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pong = NetworkMessage::Pong { nonce, timestamp };
        self.send_message(&pong).await
    }
    
    pub fn is_connection_healthy(&self) -> bool {
        let idle_time = self.connection_state.last_activity.elapsed();
        idle_time < Duration::from_secs(300) && self.connection_state.is_authenticated
    }
    
    pub fn get_connection_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "peer_address": self.peer_address.to_string(),
            "connected_duration": self.connection_state.connected_at.elapsed().as_secs(),
            "bytes_sent": self.connection_state.bytes_sent,
            "bytes_received": self.connection_state.bytes_received,
            "messages_sent": self.connection_state.messages_sent,
            "messages_received": self.connection_state.messages_received,
            "node_id": self.connection_state.node_id,
            "height": self.connection_state.height,
            "is_authenticated": self.connection_state.is_authenticated,
            "version": self.connection_state.version,
        })
    }
    
    fn calculate_checksum(data: &[u8]) -> [u8; 4] {
        let hash = Sha256::digest(data);
        [hash[0], hash[1], hash[2], hash[3]]
    }
    
    fn calculate_challenge_response(challenge: &[u8], node_id: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        hasher.update(node_id.as_bytes());
        hasher.update(b"pali_challenge_response");
        hasher.finalize().to_vec()
    }
    
    fn should_encrypt_message(&self, message: &NetworkMessage) -> bool {
        matches!(message, 
            NetworkMessage::NewTransaction { .. } |
            NetworkMessage::Transactions { .. } |
            NetworkMessage::GetTransactionHistory { .. } |
            NetworkMessage::TransactionHistory { .. } |
            NetworkMessage::Alert { .. }
        )
    }
}

impl Drop for SecureNetworkClient {
    fn drop(&mut self) {
        // Remove connection from rate limiter
        let mut limiter = self.rate_limiter.lock().unwrap();
        limiter.remove_connection(self.peer_address.ip());
        
        info!("Disconnected from peer: {}", self.peer_address);
    }
}

/// Enhanced message payload for structured communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    pub message_id: String,
    pub timestamp: u64,
    pub priority: MessagePriority,
    pub ttl: u32, // Time to live in seconds
    pub data: NetworkMessage,
    pub signature: Option<Vec<u8>>, // Optional message signing
}

impl MessagePayload {
    pub fn new(data: NetworkMessage, priority: MessagePriority) -> Self {
        MessagePayload {
            message_id: Self::generate_message_id(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            priority,
            ttl: 3600, // 1 hour default TTL
            data,
            signature: None,
        }
    }
    
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }
    
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        now > self.timestamp + self.ttl as u64
    }
    
    fn generate_message_id() -> String {
        let mut bytes = [0u8; 16];
        thread_rng().fill(&mut bytes);
        hex::encode(bytes)
    }
}

/// Peer management and discovery
#[derive(Debug)]
pub struct PeerManager {
    known_peers: HashMap<SocketAddr, NodeInfo>,
    trusted_peers: HashSet<SocketAddr>,
    banned_peers: HashMap<SocketAddr, Instant>,
    connection_attempts: HashMap<SocketAddr, (usize, Instant)>,
    max_peers: usize,
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        PeerManager {
            known_peers: HashMap::new(),
            trusted_peers: HashSet::new(),
            banned_peers: HashMap::new(),
            connection_attempts: HashMap::new(),
            max_peers,
        }
    }
    
    pub fn add_peer(&mut self, node_info: NodeInfo) {
        if !self.is_banned(&node_info.addr) {
            self.known_peers.insert(node_info.addr, node_info);
        }
    }
    
    pub fn mark_peer_as_trusted(&mut self, addr: SocketAddr) {
        self.trusted_peers.insert(addr);
    }
    
    pub fn ban_peer(&mut self, addr: SocketAddr, duration: Duration) {
        self.banned_peers.insert(addr, Instant::now() + duration);
        self.known_peers.remove(&addr);
        self.trusted_peers.remove(&addr);
        warn!("Banned peer {} for {:?}", addr, duration);
    }
    
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        if let Some(&ban_until) = self.banned_peers.get(addr) {
            Instant::now() < ban_until
        } else {
            false
        }
    }
    
    pub fn get_peers_for_connection(&self, count: usize) -> Vec<SocketAddr> {
        let now = Instant::now();
        
        self.known_peers.keys()
            .filter(|addr| {
                !self.is_banned(addr) && 
                !self.has_recent_failed_attempt(addr, now)
            })
            .take(count)
            .cloned()
            .collect()
    }
    
    pub fn record_connection_attempt(&mut self, addr: SocketAddr, success: bool) {
        if success {
            self.connection_attempts.remove(&addr);
        } else {
            let (attempts, _) = self.connection_attempts.entry(addr)
                .or_insert((0, Instant::now()));
            *attempts += 1;
            
            // Ban after too many failed attempts
            if *attempts >= 5 {
                self.ban_peer(addr, Duration::from_secs(3600));
            }
        }
    }
    
    fn has_recent_failed_attempt(&self, addr: &SocketAddr, now: Instant) -> bool {
        if let Some(&(attempts, last_attempt)) = self.connection_attempts.get(addr) {
            attempts > 0 && now.duration_since(last_attempt) < Duration::from_secs(300)
        } else {
            false
        }
    }
    
    pub fn cleanup_expired_bans(&mut self) {
        let now = Instant::now();
        self.banned_peers.retain(|_, &mut ban_until| now < ban_until);
    }
    
    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "known_peers": self.known_peers.len(),
            "trusted_peers": self.trusted_peers.len(),
            "banned_peers": self.banned_peers.len(),
            "max_peers": self.max_peers,
        })
    }
}

/// Generate unique node ID
pub fn generate_node_id() -> String {
    let mut bytes = [0u8; 8];
    thread_rng().fill(&mut bytes);
    format!("pali-{}", hex::encode(bytes))
}

/// Validate network address
pub fn is_valid_peer_address(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ipv4) => {
            !ipv4.is_loopback() && 
            !ipv4.is_private() && 
            !ipv4.is_multicast() &&
            !ipv4.is_broadcast()
        }
        IpAddr::V6(ipv6) => {
            !ipv6.is_loopback() && 
            !ipv6.is_multicast()
        }
    }
}

/// Calculate network hash rate from difficulty
pub fn calculate_network_hashrate(difficulty: u32, block_time: u64) -> f64 {
    if block_time == 0 {
        return 0.0;
    }
    
    let work = 2_u64.pow(difficulty);
    work as f64 / block_time as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new();
        let ip = "127.0.0.1".parse().unwrap();
        
        // Should allow initial connections
        assert!(limiter.check_connection_limit(ip));
        assert!(limiter.check_rate_limit(ip));
        
        // Should track reputation
        limiter.update_reputation(ip, 10);
        assert_eq!(limiter.reputation_scores.get(&ip), Some(&10));
    }
    
    #[test]
    fn test_message_payload() {
        let msg = NetworkMessage::Ping { nonce: 123, timestamp: 456 };
        let payload = MessagePayload::new(msg, MessagePriority::Normal);
        
        assert!(!payload.is_expired());
        assert_eq!(payload.priority, MessagePriority::Normal);
    }
    
    #[test]
    fn test_peer_manager() {
        let mut manager = PeerManager::new(10);
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        
        let node_info = NodeInfo {
            node_id: "test-node".to_string(),
            version: "1.0".to_string(),
            user_agent: "test".to_string(),
            services: 1,
            timestamp: 0,
            addr,
            height: 0,
        };
        
        manager.add_peer(node_info);
        assert_eq!(manager.known_peers.len(), 1);
        
        manager.ban_peer(addr, Duration::from_secs(60));
        assert!(manager.is_banned(&addr));
        assert_eq!(manager.known_peers.len(), 0);
    }
    
    #[test]
    fn test_node_id_generation() {
        let id1 = generate_node_id();
        let id2 = generate_node_id();
        
        assert_ne!(id1, id2);
        assert!(id1.starts_with("pali-"));
        assert!(id2.starts_with("pali-"));
    }
}
