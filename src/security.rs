// src/security.rs - Clean, working security implementation
use crate::types::{Transaction, Block, Hash, Address};
use crate::error::{PaliError, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::sync::{Arc, RwLock, Mutex, atomic::{AtomicU64, AtomicBool, Ordering}};
use log::{info, warn, error, debug};
use serde::{Serialize, Deserialize};

// Security constants
const MAX_CONNECTIONS_PER_IP: usize = 10;
const MAX_REQUESTS_PER_MINUTE: usize = 60;

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityManagerConfig {
    pub enable_rate_limiting: bool,
    pub enable_ip_filtering: bool,
    pub max_connections_per_ip: usize,
    pub rate_limit_window_seconds: u64,
    pub max_requests_per_window: u32,
}

impl Default for SecurityManagerConfig {
    fn default() -> Self {
        SecurityManagerConfig {
            enable_rate_limiting: true,
            enable_ip_filtering: true,
            max_connections_per_ip: 3,
            rate_limit_window_seconds: 60,
            max_requests_per_window: 60,
        }
    }
}

/// Main security manager
pub struct SecurityManager {
    config: SecurityManagerConfig,
    rate_limits: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    connections: Arc<Mutex<HashMap<String, u32>>>,
}

impl SecurityManager {
    pub fn new(config: SecurityManagerConfig) -> Self {
        SecurityManager {
            config,
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    pub fn validate_message(&self, addr: SocketAddr, _data: &[u8]) -> std::result::Result<(), String> {
        let ip = addr.ip().to_string();
        
        // Check rate limiting
        if self.config.enable_rate_limiting {
            let mut limits = self.rate_limits.lock().unwrap();
            let now = Instant::now();
            let entry = limits.entry(ip.clone()).or_insert((0, now));
            
            // Reset counter if window expired
            if now.duration_since(entry.1).as_secs() > self.config.rate_limit_window_seconds {
                entry.0 = 0;
                entry.1 = now;
            }
            
            entry.0 += 1;
            if entry.0 > self.config.max_requests_per_window {
                return Err(format!("Rate limit exceeded for {}", ip));
            }
        }
        
        // Check connection limits
        if self.config.enable_ip_filtering {
            let connections = self.connections.lock().unwrap();
            if let Some(&count) = connections.get(&ip) {
                if count >= self.config.max_connections_per_ip as u32 {
                    return Err(format!("Too many connections from {}", ip));
                }
            }
        }
        
        Ok(())
    }
    
    pub fn register_connection(&self, addr: SocketAddr) {
        let ip = addr.ip().to_string();
        let mut connections = self.connections.lock().unwrap();
        *connections.entry(ip).or_insert(0) += 1;
    }
    
    pub fn unregister_connection(&self, addr: SocketAddr) {
        let ip = addr.ip().to_string();
        let mut connections = self.connections.lock().unwrap();
        if let Some(count) = connections.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                connections.remove(&ip);
            }
        }
    }
}
