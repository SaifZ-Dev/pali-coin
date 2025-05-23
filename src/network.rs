// 🔒 ENHANCED SECURE NETWORK ADDITIONS
// Add these components to your existing network.rs file

use std::collections::VecDeque;
use tokio::sync::RwLock as TokioRwLock;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicI32};

/// 🛡️ ADVANCED CONNECTION SECURITY MANAGER
#[derive(Debug)]
pub struct ConnectionSecurityManager {
    // Connection tracking
    active_connections: Arc<TokioRwLock<HashMap<SocketAddr, ConnectionSecurityInfo>>>,
    ip_connection_count: Arc<DashMap<IpAddr, AtomicU32>>,
    subnet_connection_count: Arc<DashMap<String, AtomicU32>>,
    
    // Rate limiting with sliding windows
    request_windows: Arc<DashMap<IpAddr, VecDeque<Instant>>>,
    byte_windows: Arc<DashMap<IpAddr, VecDeque<(Instant, usize)>>>,
    
    // Security violations tracking
    violation_history: Arc<DashMap<IpAddr, VecDeque<SecurityViolation>>>,
    reputation_scores: Arc<DashMap<IpAddr, AtomicI32>>,
    
    // Temporary bans with automatic expiry
    temp_bans: Arc<TokioRwLock<HashMap<IpAddr, BanInfo>>>,
    permanent_bans: Arc<RwLock<HashSet<IpAddr>>>,
    
    // Configuration
    config: SecurityConfig,
}

#[derive(Debug, Clone)]
pub struct ConnectionSecurityInfo {
    pub peer_addr: SocketAddr,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub total_requests: u64,
    pub total_bytes: u64,
    pub violation_count: u32,
    pub reputation_score: i32,
    pub user_agent: Option<String>,
    pub node_version: Option<String>,
    pub is_authenticated: bool,
    pub authentication_level: AuthenticationLevel,
    pub connection_type: ConnectionType,
}

#[derive(Debug, Clone)]
pub enum AuthenticationLevel {
    None,
    Basic,
    Verified,
    Trusted,
    Administrative,
}

#[derive(Debug, Clone)]
pub enum ConnectionType {
    Unknown,
    FullNode,
    LightClient,
    Miner,
    Explorer,
    Exchange,
}

#[derive(Debug, Clone)]
pub struct SecurityViolation {
    pub violation_type: ViolationType,
    pub timestamp: Instant,
    pub severity: ViolationSeverity,
    pub description: String,
    pub related_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    RateLimitExceeded,
    InvalidMessage,
    AuthenticationFailure,
    SuspiciousPattern,
    InvalidBlock,
    InvalidTransaction,
    TimestampManipulation,
    ConnectionFlood,
    MessageFlood,
    DataSizeViolation,
}

#[derive(Debug, Clone)]
pub enum ViolationSeverity {
    Low = 1,
    Medium = 5,
    High = 10,
    Critical = 25,
}

#[derive(Debug, Clone)]
pub struct BanInfo {
    pub banned_at: Instant,
    pub expires_at: Instant,
    pub reason: String,
    pub violation_count: u32,
    pub ban_level: BanLevel,
}

#[derive(Debug, Clone)]
pub enum BanLevel {
    Warning,      // No actual ban, just warning
    Temporary,    // Short-term ban (minutes to hours)
    Extended,     // Longer ban (hours to days)
    Permanent,    // Indefinite ban
}

impl ConnectionSecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        ConnectionSecurityManager {
            active_connections: Arc::new(TokioRwLock::new(HashMap::new())),
            ip_connection_count: Arc::new(DashMap::new()),
            subnet_connection_count: Arc::new(DashMap::new()),
            request_windows: Arc::new(DashMap::new()),
            byte_windows: Arc::new(DashMap::new()),
            violation_history: Arc::new(DashMap::new()),
            reputation_scores: Arc::new(DashMap::new()),
            temp_bans: Arc::new(TokioRwLock::new(HashMap::new())),
            permanent_bans: Arc::new(RwLock::new(HashSet::new())),
            config,
        }
    }
    
    /// 🔒 CHECK IF CONNECTION IS ALLOWED
    pub async fn check_connection_allowed(&self, addr: SocketAddr) -> Result<(), String> {
        let ip = addr.ip();
        
        // 1. Check permanent bans
        {
            let permanent_bans = self.permanent_bans.read().unwrap();
            if permanent_bans.contains(&ip) {
                return Err("IP permanently banned".to_string());
            }
        }
        
        // 2. Check temporary bans
        {
            let temp_bans = self.temp_bans.read().await;
            if let Some(ban_info) = temp_bans.get(&ip) {
                if Instant::now() < ban_info.expires_at {
                    return Err(format!("IP temporarily banned: {}", ban_info.reason));
                }
            }
        }
        
        // 3. Check IP connection limit
        let ip_count = self.ip_connection_count.get(&ip)
            .map(|entry| entry.load(Ordering::Relaxed))
            .unwrap_or(0);
        
        if ip_count >= self.config.max_connections_per_ip as u32 {
            self.add_violation(ip, ViolationType::ConnectionFlood, ViolationSeverity::Medium,
                "Too many connections from IP".to_string()).await;
            return Err("IP connection limit exceeded".to_string());
        }
        
        // 4. Check subnet connection limit (for IPv4)
        if let IpAddr::V4(ipv4) = ip {
            let subnet = format!("{}.{}.{}.0/24", ipv4.octets()[0], ipv4.octets()[1], ipv4.octets()[2]);
            let subnet_count = self.subnet_connection_count.get(&subnet)
                .map(|entry| entry.load(Ordering::Relaxed))
                .unwrap_or(0);
            
            if subnet_count >= self.config.max_connections_per_subnet as u32 {
                self.add_violation(ip, ViolationType::ConnectionFlood, ViolationSeverity::Medium,
                    "Too many connections from subnet".to_string()).await;
                return Err("Subnet connection limit exceeded".to_string());
            }
        }
        
        // 5. Check reputation score
        let reputation = self.reputation_scores.get(&ip)
            .map(|entry| entry.load(Ordering::Relaxed))
            .unwrap_or(0);
        
        if reputation < -50 {
            return Err("IP reputation too low".to_string());
        }
        
        Ok(())
    }
    
    /// 📝 REGISTER NEW CONNECTION
    pub async fn register_connection(&self, addr: SocketAddr, user_agent: Option<String>) -> ConnectionSecurityInfo {
        let ip = addr.ip();
        let now = Instant::now();
        
        // Update connection counts
        self.ip_connection_count.entry(ip)
            .or_insert_with(|| AtomicU32::new(0))
            .fetch_add(1, Ordering::Relaxed);
        
        if let IpAddr::V4(ipv4) = ip {
            let subnet = format!("{}.{}.{}.0/24", ipv4.octets()[0], ipv4.octets()[1], ipv4.octets()[2]);
            self.subnet_connection_count.entry(subnet)
                .or_insert_with(|| AtomicU32::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }
        
        // Create connection info
        let connection_info = ConnectionSecurityInfo {
            peer_addr: addr,
            connected_at: now,
            last_activity: now,
            total_requests: 0,
            total_bytes: 0,
            violation_count: 0,
            reputation_score: self.reputation_scores.get(&ip)
                .map(|entry| entry.load(Ordering::Relaxed))
                .unwrap_or(0),
            user_agent: user_agent.clone(),
            node_version: None,
            is_authenticated: false,
            authentication_level: AuthenticationLevel::None,
            connection_type: ConnectionType::Unknown,
        };
        
        // Register connection
        {
            let mut connections = self.active_connections.write().await;
            connections.insert(addr, connection_info.clone());
        }
        
        info!("✅ Connection registered: {} ({})", addr, user_agent.unwrap_or_else(|| "unknown".to_string()));
        connection_info
    }
    
    /// 🔍 CHECK RATE LIMITS
    pub async fn check_rate_limits(&self, ip: IpAddr, message_size: usize) -> bool {
        let now = Instant::now();
        
        // Check request rate limit with sliding window
        {
            let mut window = self.request_windows.entry(ip).or_insert_with(VecDeque::new);
            
            // Remove old entries (older than 1 minute)
            while let Some(&front_time) = window.front() {
                if now.duration_since(front_time) > Duration::from_secs(60) {
                    window.pop_front();
                } else {
                    break;
                }
            }
            
            // Check if limit exceeded
            if window.len() >= self.config.max_requests_per_minute as usize {
                self.add_violation(ip, ViolationType::RateLimitExceeded, ViolationSeverity::Medium,
                    format!("Request rate limit exceeded: {} req/min", window.len())).await;
                return false;
            }
            
            // Add current request
            window.push_back(now);
        }
        
        // Check byte rate limit with sliding window
        {
            let mut window = self.byte_windows.entry(ip).or_insert_with(VecDeque::new);
            
            // Remove old entries (older than 1 minute)
            while let Some(&(front_time, _)) = window.front() {
                if now.duration_since(front_time) > Duration::from_secs(60) {
                    window.pop_front();
                } else {
                    break;
                }
            }
            
            // Calculate total bytes in window
            let total_bytes: usize = window.iter().map(|(_, size)| *size).sum();
            
            // Check if limit exceeded
            if total_bytes + message_size > self.config.max_bytes_per_minute as usize {
                self.add_violation(ip, ViolationType::RateLimitExceeded, ViolationSeverity::Medium,
                    format!("Byte rate limit exceeded: {} bytes/min", total_bytes)).await;
                return false;
            }
            
            // Add current message
            window.push_back((now, message_size));
        }
        
        true
    }
    
    /// 🚨 ADD SECURITY VIOLATION
    pub async fn add_violation(&self, ip: IpAddr, violation_type: ViolationType, severity: ViolationSeverity, description: String) {
        let violation = SecurityViolation {
            violation_type: violation_type.clone(),
            timestamp: Instant::now(),
            severity: severity.clone(),
            description: description.clone(),
            related_data: None,
        };
        
        // Add to violation history
        {
            let mut history = self.violation_history.entry(ip).or_insert_with(VecDeque::new);
            history.push_back(violation.clone());
            
            // Keep only last 100 violations
            if history.len() > 100 {
                history.pop_front();
            }
        }
        
        // Update reputation score
        let reputation_delta = -(severity as i32);
        self.reputation_scores.entry(ip)
            .or_insert_with(|| AtomicI32::new(0))
            .fetch_add(reputation_delta, Ordering::Relaxed);
        
        // Check if ban is needed
        let violation_count = self.violation_history.get(&ip)
            .map(|history| history.len())
            .unwrap_or(0);
        
        let current_reputation = self.reputation_scores.get(&ip)
            .map(|entry| entry.load(Ordering::Relaxed))
            .unwrap_or(0);
        
        // Determine ban action based on severity and history
        let ban_action = match (&violation_type, &severity, violation_count, current_reputation) {
            (ViolationType::ConnectionFlood, ViolationSeverity::Critical, _, _) => Some((Duration::from_secs(3600), BanLevel::Extended)),
            (ViolationType::MessageFlood, ViolationSeverity::High, _, _) => Some((Duration::from_secs(1800), BanLevel::Temporary)),
            (ViolationType::InvalidBlock, ViolationSeverity::High, count, _) if count >= 3 => Some((Duration::from_secs(7200), BanLevel::Extended)),
            (ViolationType::AuthenticationFailure, _, count, _) if count >= 5 => Some((Duration::from_secs(900), BanLevel::Temporary)),
            (_, _, _, rep) if rep < -100 => Some((Duration::from_secs(3600), BanLevel::Extended)),
            (_, _, count, _) if count >= 20 => Some((Duration::from_secs(1800), BanLevel::Temporary)),
            _ => None,
        };
        
        if let Some((duration, ban_level)) = ban_action {
            self.apply_temporary_ban(ip, duration, ban_level, description.clone()).await;
        }
        
        warn!("🚨 Security violation from {}: {:?} - {} (reputation: {})", 
              ip, violation_type, description, current_reputation);
    }
    
    /// 🚫 APPLY TEMPORARY BAN
    pub async fn apply_temporary_ban(&self, ip: IpAddr, duration: Duration, ban_level: BanLevel, reason: String) {
        let now = Instant::now();
        let expires_at = now + duration;
        
        let ban_info = BanInfo {
            banned_at: now,
            expires_at,
            reason: reason.clone(),
            violation_count: self.violation_history.get(&ip)
                .map(|history| history.len() as u32)
                .unwrap_or(0),
            ban_level: ban_level.clone(),
        };
        
        {
            let mut temp_bans = self.temp_bans.write().await;
            temp_bans.insert(ip, ban_info);
        }
        
        // Disconnect all existing connections from this IP
        self.disconnect_ip_connections(ip).await;
        
        warn!("🚫 Applied {:?} ban to {} for {:?}: {}", ban_level, ip, duration, reason);
    }
    
    /// 🔌 DISCONNECT ALL CONNECTIONS FROM IP
    pub async fn disconnect_ip_connections(&self, ip: IpAddr) {
        let mut connections_to_remove = Vec::new();
        
        {
            let connections = self.active_connections.read().await;
            for (addr, _) in connections.iter() {
                if addr.ip() == ip {
                    connections_to_remove.push(*addr);
                }
            }
        }
        
        for addr in connections_to_remove {
            self.unregister_connection(addr).await;
        }
    }
    
    /// 📤 UNREGISTER CONNECTION
    pub async fn unregister_connection(&self, addr: SocketAddr) {
        let ip = addr.ip();
        
        // Remove from active connections
        {
            let mut connections = self.active_connections.write().await;
            connections.remove(&addr);
        }
        
        // Update connection counts
        if let Some(counter) = self.ip_connection_count.get(&ip) {
            let new_count = counter.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);
            if new_count == 0 {
                self.ip_connection_count.remove(&ip);
            }
        }
        
        if let IpAddr::V4(ipv4) = ip {
            let subnet = format!("{}.{}.{}.0/24", ipv4.octets()[0], ipv4.octets()[1], ipv4.octets()[2]);
            if let Some(counter) = self.subnet_connection_count.get(&subnet) {
                let new_count = counter.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);
                if new_count == 0 {
                    self.subnet_connection_count.remove(&subnet);
                }
            }
        }
        
        debug!("🔌 Connection unregistered: {}", addr);
    }
    
    /// 🧹 CLEANUP EXPIRED DATA
    pub async fn cleanup_expired_data(&self) {
        let now = Instant::now();
        
        // Cleanup expired temporary bans
        {
            let mut temp_bans = self.temp_bans.write().await;
            temp_bans.retain(|_, ban_info| now < ban_info.expires_at);
        }
        
        // Cleanup old violation history (keep last 24 hours)
        self.violation_history.retain(|_, history| {
            history.retain(|violation| now.duration_since(violation.timestamp) < Duration::from_secs(86400));
            !history.is_empty()
        });
        
        // Cleanup old rate limit windows
        self.request_windows.retain(|_, window| {
            window.retain(|&timestamp| now.duration_since(timestamp) < Duration::from_secs(120));
            !window.is_empty()
        });
        
        self.byte_windows.retain(|_, window| {
            window.retain(|(timestamp, _)| now.duration_since(*timestamp) < Duration::from_secs(120));
            !window.is_empty()
        });
        
        // Cleanup inactive connections (no activity for 30 minutes)
        let mut inactive_connections = Vec::new();
        {
            let connections = self.active_connections.read().await;
            for (addr, info) in connections.iter() {
                if now.duration_since(info.last_activity) > Duration::from_secs(1800) {
                    inactive_connections.push(*addr);
                }
            }
        }
        
        for addr in inactive_connections {
            self.unregister_connection(addr).await;
            info!("🧹 Cleaned up inactive connection: {}", addr);
        }
    }
    
    /// 📊 GET SECURITY STATISTICS
    pub async fn get_security_stats(&self) -> serde_json::Value {
        let connections = self.active_connections.read().await;
        let temp_bans = self.temp_bans.read().await;
        let permanent_bans = self.permanent_bans.read().unwrap();
        
        let total_violations: usize = self.violation_history.iter()
            .map(|entry| entry.value().len())
            .sum();
        
        let active_ips: HashSet<IpAddr> = connections.keys()
            .map(|addr| addr.ip())
            .collect();
        
        serde_json::json!({
            "connections": {
                "active_count": connections.len(),
                "unique_ips": active_ips.len(),
                "total_capacity": self.config.max_connections,
            },
            "security": {
                "temporary_bans": temp_bans.len(),
                "permanent_bans": permanent_bans.len(),
                "total_violations": total_violations,
                "violation_types_tracked": self.violation_history.len(),
            },
            "rate_limiting": {
                "request_windows_active": self.request_windows.len(),
                "byte_windows_active": self.byte_windows.len(),
                "max_requests_per_minute": self.config.max_requests_per_minute,
                "max_bytes_per_minute": self.config.max_bytes_per_minute,
            },
            "reputation": {
                "tracked_ips": self.reputation_scores.len(),
                "average_reputation": self.reputation_scores.iter()
                    .map(|entry| entry.value().load(Ordering::Relaxed))
                    .sum::<i32>() as f64 / self.reputation_scores.len().max(1) as f64,
            }
        })
    }
    
    /// 🎯 GET CONNECTION INFO
    pub async fn get_connection_info(&self, addr: SocketAddr) -> Option<ConnectionSecurityInfo> {
        let connections = self.active_connections.read().await;
        connections.get(&addr).cloned()
    }
    
    /// ✅ UPDATE CONNECTION ACTIVITY
    pub async fn update_connection_activity(&self, addr: SocketAddr, request_size: usize) {
        let mut connections = self.active_connections.write().await;
        if let Some(info) = connections.get_mut(&addr) {
            info.last_activity = Instant::now();
            info.total_requests += 1;
            info.total_bytes += request_size as u64;
        }
    }
    
    /// 🔐 SET AUTHENTICATION LEVEL
    pub async fn set_authentication_level(&self, addr: SocketAddr, level: AuthenticationLevel) {
        let mut connections = self.active_connections.write().await;
        if let Some(info) = connections.get_mut(&addr) {
            info.authentication_level = level;
            info.is_authenticated = !matches!(info.authentication_level, AuthenticationLevel::None);
        }
    }
}

/// 🔒 SECURE MESSAGE VALIDATOR
pub struct SecureMessageValidator {
    config: SecurityConfig,
}

impl SecureMessageValidator {
    pub fn new(config: SecurityConfig) -> Self {
        SecureMessageValidator { config }
    }
    
    /// 🔍 VALIDATE MESSAGE SECURITY
    pub fn validate_message_security(&self, message: &NetworkMessage, sender_ip: IpAddr) -> Result<(), String> {
        // 1. Message size validation
        let serialized = bincode::serialize(message)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        if serialized.len() > MAX_MESSAGE_SIZE {
            return Err(format!("Message too large: {} bytes", serialized.len()));
        }
        
        // 2. Message type specific validation
        match message {
            NetworkMessage::SubmitBlock { block } => {
                self.validate_block_message_security(block)?;
            }
            NetworkMessage::NewTransaction { transaction, .. } => {
                self.validate_transaction_message_security(transaction)?;
            }
            NetworkMessage::GetBlocks { start_height, end_height, max_blocks } => {
                if *max_blocks > 100 {
                    return Err("Too many blocks requested".to_string());
                }
                if *end_height < *start_height {
                    return Err("Invalid height range".to_string());
                }
            }
            NetworkMessage::GetTransactions { hashes } => {
                if hashes.len() > 50 {
                    return Err("Too many transactions requested".to_string());
                }
            }
            _ => {} // Other messages have basic validation
        }
        
        // 3. Anti-spam validation
        self.validate_anti_spam(message, sender_ip)?;
        
        Ok(())
    }
    
    fn validate_block_message_security(&self, block: &Block) -> Result<(), String> {
        // Block-specific security validation
        let block_data = bincode::serialize(block)
            .map_err(|e| format!("Block serialization error: {}", e))?;
        
        if block_data.len() > self.config.max_block_size {
            return Err(format!("Block too large: {} bytes", block_data.len()));
        }
        
        if block.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
            return Err("Too many transactions in block".to_string());
        }
        
        // Validate block structure
        if block.transactions.is_empty() {
            return Err("Block cannot be empty".to_string());
        }
        
        // Validate coinbase
        if !block.transactions[0].is_coinbase() {
            return Err("First transaction must be coinbase".to_string());
        }
        
        Ok(())
    }
    
    fn validate_transaction_message_security(&self, tx: &Transaction) -> Result<(), String> {
        // Transaction-specific security validation
        let tx_data = bincode::serialize(tx)
            .map_err(|e| format!("Transaction serialization error: {}", e))?;
        
        if tx_data.len() > self.config.max_transaction_size {
            return Err(format!("Transaction too large: {} bytes", tx_data.len()));
        }
        
        if !tx.is_coinbase() && tx.fee < self.config.min_transaction_fee {
            return Err("Transaction fee too low".to_string());
        }
        
        // Additional security checks
        if tx.amount == 0 && !tx.is_coinbase() {
            return Err("Zero amount transaction not allowed".to_string());
        }
        
        Ok(())
    }
    
    fn validate_anti_spam(&self, message: &NetworkMessage, _sender_ip: IpAddr) -> Result<(), String> {
        // Anti-spam validation based on message patterns
        match message {
            NetworkMessage::Ping { nonce, .. } => {
                if *nonce == 0 {
                    return Err("Invalid ping nonce".to_string());
                }
            }
            NetworkMessage::GetBalance { address } => {
                if address.len() != 40 && !address.starts_with("0x") {
                    return Err("Invalid address format".to_string());
                }
            }
            _ => {}
        }
        
        Ok(())
    }
}

/// 🔧 HELPER FUNCTION TO CREATE SECURE CLIENT WITH STREAM
impl SecureNetworkClient {
    pub async fn connect_with_stream(
        stream: TcpStream,
        peer_address: SocketAddr,
        rate_limiter: Arc<Mutex<RateLimiter>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let connection_state = ConnectionState {
            addr: peer_address,
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
        
        Ok(SecureNetworkClient {
            stream,
            peer_address,
            connection_state,
            rate_limiter,
            security: MessageSecurity::new(),
            last_ping: Instant::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_connection_security_manager() {
        let config = SecurityConfig::default();
        let manager = ConnectionSecurityManager::new(config);
        
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        
        // Test connection registration
        assert!(manager.check_connection_allowed(addr).await.is_ok());
        
        let _info = manager.register_connection(addr, Some("test-agent".to_string())).await;
        
        // Test rate limiting
        assert!(manager.check_rate_limits(addr.ip(), 100).await);
        
        manager.unregister_connection(addr).await;
    }
    
    #[test]
    fn test_secure_message_validator() {
        let config = SecurityConfig::default();
        let validator = SecureMessageValidator::new(config);
        
        let ping = NetworkMessage::Ping { nonce: 123, timestamp: 456 };
        let ip = "127.0.0.1".parse().unwrap();
        
        assert!(validator.validate_message_security(&ping, ip).is_ok());
        
        let invalid_ping = NetworkMessage::Ping { nonce: 0, timestamp: 456 };
        assert!(validator.validate_message_security(&invalid_ping, ip).is_err());
    }
}
