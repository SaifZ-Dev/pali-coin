// src/utils.rs - Enterprise-grade utility functions for Pali Coin
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use crate::error::{PaliError, Result};
use crate::types::{Hash, Address};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::fs;
use rand::{Rng, RngCore, thread_rng};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, ecdsa::Signature};
use chrono::{DateTime, Utc, TimeZone};
use log::{debug, warn, error, info};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// Constants for validation and limits
const MAX_MONEY_SUPPLY: u64 = 21_000_000 * 100_000_000; // 21M PALI with 8 decimals
const MIN_TX_FEE: u64 = 1000; // 0.00001 PALI minimum fee
const MAX_TX_SIZE: usize = 100_000; // 100KB max transaction size
const MAX_BLOCK_SIZE: usize = 4_000_000; // 4MB max block size
const COIN_PRECISION: u8 = 8; // 8 decimal places like Bitcoin
const SATOSHI_PER_COIN: u64 = 100_000_000; // 1 PALI = 100M satoshis

/// Global counters for monitoring and statistics
static TX_COUNTER: AtomicU64 = AtomicU64::new(0);
static BLOCK_COUNTER: AtomicU64 = AtomicU64::new(0);
static PEER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Hash utilities for cryptographic operations
pub mod hash {
    use super::*;
    
    /// Calculate SHA-256 hash (single round)
    pub fn sha256(data: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Calculate double SHA-256 hash (Bitcoin-style)
    pub fn double_sha256(data: &[u8]) -> Hash {
        let first_hash = sha256(data);
        sha256(&first_hash)
    }
    
    /// Calculate RIPEMD160 hash
    pub fn ripemd160(data: &[u8]) -> [u8; 20] {
        let mut hasher = Ripemd160::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Calculate Bitcoin-style address hash (SHA256 + RIPEMD160)
    pub fn hash160(data: &[u8]) -> [u8; 20] {
        let sha_hash = sha256(data);
        ripemd160(&sha_hash)
    }
    
    /// Calculate merkle root from a list of hashes (Bitcoin-compatible)
    pub fn merkle_root(hashes: &[Hash]) -> Hash {
        if hashes.is_empty() {
            return [0; 32];
        }
        
        if hashes.len() == 1 {
            return hashes[0];
        }
        
        let mut current_level = hashes.to_vec();
        
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() == 2 {
                    chunk[1]
                } else {
                    // If odd number, duplicate the last hash (Bitcoin standard)
                    chunk[0]
                };
                
                // Concatenate and double hash
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&left);
                combined.extend_from_slice(&right);
                
                next_level.push(double_sha256(&combined));
            }
            
            current_level = next_level;
        }
        
        current_level[0]
    }
    
    /// Verify merkle proof for a transaction
    pub fn verify_merkle_proof(
        tx_hash: &Hash,
        merkle_path: &[Hash],
        merkle_root: &Hash,
        index: usize,
    ) -> bool {
        let mut current_hash = *tx_hash;
        let mut current_index = index;
        
        for proof_hash in merkle_path {
            let mut combined = Vec::with_capacity(64);
            
            if current_index % 2 == 0 {
                // Current hash is on the left
                combined.extend_from_slice(&current_hash);
                combined.extend_from_slice(proof_hash);
            } else {
                // Current hash is on the right
                combined.extend_from_slice(proof_hash);
                combined.extend_from_slice(&current_hash);
            }
            
            current_hash = double_sha256(&combined);
            current_index /= 2;
        }
        
        current_hash == *merkle_root
    }
    
    /// Generate deterministic hash from seed
    pub fn deterministic_hash(seed: &[u8], nonce: u64) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(seed);
        data.extend_from_slice(&nonce.to_be_bytes());
        double_sha256(&data)
    }
}

/// Time utilities for blockchain timestamps and validation
pub mod time {
    use super::*;
    
    /// Get current timestamp in seconds since Unix epoch
    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    
    /// Get current timestamp in milliseconds since Unix epoch
    pub fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
    
    /// Get current timestamp in nanoseconds for high precision
    pub fn now_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }
    
    /// Convert timestamp to human-readable format
    pub fn format_timestamp(timestamp: u64) -> String {
        let dt = Utc.timestamp_opt(timestamp as i64, 0)
            .single()
            .unwrap_or_else(|| Utc::now());
        
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }
    
    /// Convert timestamp to ISO 8601 format
    pub fn format_iso8601(timestamp: u64) -> String {
        let dt = Utc.timestamp_opt(timestamp as i64, 0)
            .single()
            .unwrap_or_else(|| Utc::now());
        
        dt.to_rfc3339()
    }
    
    /// Check if timestamp is within acceptable range for blocks
    pub fn is_valid_block_timestamp(timestamp: u64, max_drift_seconds: u64) -> bool {
        let current = now();
        let max_future = current + max_drift_seconds;
        let min_past = current.saturating_sub(max_drift_seconds * 100); // Allow old blocks
        
        timestamp >= min_past && timestamp <= max_future
    }
    
    /// Check if timestamp is valid for transactions
    pub fn is_valid_tx_timestamp(timestamp: u64, max_drift_seconds: u64) -> bool {
        let current = now();
        let max_future = current + max_drift_seconds;
        let min_past = current.saturating_sub(3600); // 1 hour in past max
        
        timestamp >= min_past && timestamp <= max_future
    }
    
    /// Calculate duration between timestamps
    pub fn duration_between(start: u64, end: u64) -> Duration {
        Duration::from_secs(end.saturating_sub(start))
    }
    
    /// Format duration in human-readable form
    pub fn format_duration(duration: Duration) -> String {
        let total_seconds = duration.as_secs();
        let days = total_seconds / 86400;
        let hours = (total_seconds % 86400) / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;
        
        if days > 0 {
            format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
        } else if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        }
    }
}

/// Encoding utilities for data serialization and formatting
pub mod encoding {
    use super::*;
    use base64::{Engine as _, engine::general_purpose};
    use base58::ToBase58;
    
    /// Encode bytes to hexadecimal string (lowercase)
    pub fn to_hex(data: &[u8]) -> String {
        hex::encode(data)
    }
    
    /// Encode bytes to hexadecimal string (uppercase)
    pub fn to_hex_upper(data: &[u8]) -> String {
        hex::encode_upper(data)
    }
    
    /// Decode hexadecimal string to bytes
    pub fn from_hex(hex_str: &str) -> Result<Vec<u8>> {
        hex::decode(hex_str.trim_start_matches("0x"))
            .map_err(|e| PaliError::Parse(format!("Invalid hex: {}", e)))
    }
    
    /// Encode bytes to base64 string
    pub fn to_base64(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }
    
    /// Decode base64 string to bytes
    pub fn from_base64(base64_str: &str) -> Result<Vec<u8>> {
        general_purpose::STANDARD.decode(base64_str)
            .map_err(|e| PaliError::Parse(format!("Invalid base64: {}", e)))
    }
    
    /// Encode bytes to base58 string (Bitcoin-style)
    pub fn to_base58(data: &[u8]) -> String {
        bs58::encode(data).into_string()
    }
    
    /// Decode base58 string to bytes
    pub fn from_base58(base58_str: &str) -> Result<Vec<u8>> {
        bs58::decode(base58_str)
            .into_vec()
            .map_err(|e| PaliError::Parse(format!("Invalid base58: {}", e)))
    }
    
    /// Encode address to string representation (hex)
    pub fn address_to_string(address: &Address) -> String {
        format!("0x{}", to_hex(address))
    }
    
    /// Decode string to address
    pub fn string_to_address(address_str: &str) -> Result<Address> {
        let clean_str = address_str.trim_start_matches("0x");
        let bytes = from_hex(clean_str)?;
        
        if bytes.len() != 20 {
            return Err(PaliError::InvalidAddress(format!(
                "Address must be 20 bytes, got {}", bytes.len()
            )));
        }
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&bytes);
        Ok(address)
    }
    
    /// Validate address string format
    pub fn is_valid_address_string(address_str: &str) -> bool {
        let clean_str = address_str.trim_start_matches("0x");
        clean_str.len() == 40 && 
        clean_str.chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// Encode hash to string
    pub fn hash_to_string(hash: &Hash) -> String {
        format!("0x{}", to_hex(hash))
    }
    
    /// Decode string to hash
    pub fn string_to_hash(hash_str: &str) -> Result<Hash> {
        let clean_str = hash_str.trim_start_matches("0x");
        let bytes = from_hex(clean_str)?;
        
        if bytes.len() != 32 {
            return Err(PaliError::Parse(format!(
                "Hash must be 32 bytes, got {}", bytes.len()
            )));
        }
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(hash)
    }
    
    /// Format bytes with proper units (KB, MB, GB)
    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;
        
        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        
        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size, UNITS[unit_index])
        }
    }
}

/// Validation utilities for blockchain data integrity
pub mod validation {
    use super::*;
    
    /// Check if hash meets difficulty requirement (leading zero bits)
    pub fn meets_difficulty(hash: &Hash, difficulty: u32) -> bool {
        let mut count = 0u32;
        
        for byte in hash {
            if *byte == 0 {
                count += 8;
                continue;
            }
            
            // Count leading zero bits in this byte
            let mut byte_val = *byte;
            while byte_val & 0x80 == 0 {
                count += 1;
                byte_val <<= 1;
            }
            break;
        }
        
        count >= difficulty
    }
    
    /// Validate transaction amount (must be positive and within limits)
    pub fn is_valid_amount(amount: u64) -> bool {
        amount > 0 && amount <= MAX_MONEY_SUPPLY
    }
    
    /// Validate transaction fee (reasonable range)
    pub fn is_valid_fee(fee: u64, amount: u64) -> bool {
        fee >= MIN_TX_FEE && 
        fee <= amount.saturating_div(2) && // Max 50% fee
        fee <= 1_000_000_000 // Max 10 PALI fee
    }
    
    /// Validate block size
    pub fn is_valid_block_size(block_size: usize) -> bool {
        block_size > 0 && block_size <= MAX_BLOCK_SIZE
    }
    
    /// Validate transaction size
    pub fn is_valid_tx_size(tx_size: usize) -> bool {
        tx_size > 0 && tx_size <= MAX_TX_SIZE
    }
    
    /// Validate network port
    pub fn is_valid_port(port: u16) -> bool {
        port >= 1024 && port <= 65535
    }
    
    /// Validate difficulty target (reasonable range)
    pub fn is_valid_difficulty(difficulty: u32) -> bool {
        difficulty >= 1 && difficulty <= 32
    }
    
    /// Validate block height sequence
    pub fn is_valid_block_height(height: u64, previous_height: u64) -> bool {
        height == previous_height + 1
    }
    
    /// Validate nonce range
    pub fn is_valid_nonce(nonce: u64, previous_nonce: u64) -> bool {
        nonce > previous_nonce // Prevent replay attacks
    }
    
    /// Check if signature is valid format
    pub fn is_valid_signature_format(signature: &[u8]) -> bool {
        signature.len() == 64 || signature.len() == 65 // Standard or recoverable
    }
    
    /// Check if public key is valid format
    pub fn is_valid_public_key_format(pubkey: &[u8]) -> bool {
        pubkey.len() == 33 || pubkey.len() == 65 // Compressed or uncompressed
    }
    
    /// Validate chain ID
    pub fn is_valid_chain_id(chain_id: u64) -> bool {
        chain_id > 0 && chain_id <= 0xFFFFFFFF // 32-bit max
    }
}

/// Random utilities for secure random generation
pub mod random {
    use super::*;
    use rand::distributions::Alphanumeric;
    use rand::prelude::*;
    
    /// Generate cryptographically secure random bytes
    pub fn secure_bytes(len: usize) -> Vec<u8> {
        let mut rng = thread_rng();
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }
    
    /// Generate random hash
    pub fn hash() -> Hash {
        let mut rng = thread_rng();
        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        hash
    }
    
    /// Generate random address
    pub fn address() -> Address {
        let mut rng = thread_rng();
        let mut addr = [0u8; 20];
        rng.fill_bytes(&mut addr);
        addr
    }
    
    /// Generate random nonce
    pub fn nonce() -> u64 {
        thread_rng().gen()
    }
    
    /// Generate random string of given length
    pub fn string(len: usize) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }
    
    /// Generate random alphanumeric string
    pub fn alphanumeric(len: usize) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }
    
    /// Generate random hex string
    pub fn hex_string(len: usize) -> String {
        let bytes = secure_bytes(len / 2 + 1);
        encoding::to_hex(&bytes)[..len].to_string()
    }
    
    /// Generate random number in range
    pub fn range(min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }
        thread_rng().gen_range(min..=max)
    }
}

/// Mathematical utilities for blockchain calculations
pub mod math {
    use super::*;
    
    /// Calculate difficulty adjustment (Bitcoin-style)
    pub fn calculate_difficulty_adjustment(
        current_difficulty: u32,
        actual_time: u64,
        target_time: u64,
    ) -> u32 {
        if actual_time == 0 || target_time == 0 {
            return current_difficulty;
        }
        
        // Calculate adjustment factor (limit to 4x change)
        let adjustment_factor = if actual_time < target_time / 4 {
            4.0
        } else if actual_time > target_time * 4 {
            0.25
        } else {
            target_time as f64 / actual_time as f64
        };
        
        let new_difficulty = (current_difficulty as f64 * adjustment_factor) as u32;
        new_difficulty.clamp(1, 32)
    }
    
    /// Calculate compound interest for staking rewards
    pub fn compound_interest(principal: u64, rate: f64, periods: u64) -> u64 {
        if rate <= 0.0 || periods == 0 {
            return principal;
        }
        
        let result = principal as f64 * (1.0 + rate).powi(periods as i32);
        result.round() as u64
    }
    
    /// Calculate percentage
    pub fn percentage(value: u64, total: u64) -> f64 {
        if total == 0 {
            0.0
        } else {
            (value as f64 / total as f64) * 100.0
        }
    }
    
    /// Calculate moving average
    pub fn moving_average(values: &[f64], window: usize) -> Vec<f64> {
        if values.is_empty() || window == 0 {
            return Vec::new();
        }
        
        let mut result = Vec::new();
        for i in window..=values.len() {
            let sum: f64 = values[i-window..i].iter().sum();
            result.push(sum / window as f64);
        }
        result
    }
    
    /// Calculate standard deviation
    pub fn standard_deviation(values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }
        
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        
        variance.sqrt()
    }
    
    /// Calculate hash rate from difficulty and time
    pub fn calculate_hashrate(difficulty: u32, block_time: u64) -> f64 {
        if block_time == 0 {
            return 0.0;
        }
        
        let work = 2_u64.pow(difficulty);
        work as f64 / block_time as f64
    }
    
    /// Calculate target block time based on hashrate and difficulty
    pub fn calculate_target_time(hashrate: f64, difficulty: u32) -> u64 {
        if hashrate <= 0.0 {
            return u64::MAX;
        }
        
        let work = 2_u64.pow(difficulty);
        (work as f64 / hashrate) as u64
    }
    
    /// Convert satoshis to PALI with proper precision
    pub fn satoshis_to_pali(satoshis: u64) -> f64 {
        satoshis as f64 / SATOSHI_PER_COIN as f64
    }
    
    /// Convert PALI to satoshis
    pub fn pali_to_satoshis(pali: f64) -> u64 {
        (pali * SATOSHI_PER_COIN as f64).round() as u64
    }
}

/// Network utilities for P2P networking and validation
pub mod network {
    use super::*;
    
    /// Check if IP address is in private range
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || 
                ipv4.is_loopback() || 
                ipv4.is_link_local() ||
                ipv4.is_multicast() ||
                ipv4.is_broadcast()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || 
                ipv6.is_multicast() ||
                ipv6.is_unspecified()
            }
        }
    }
    
    /// Check if IP is localhost
    pub fn is_localhost(addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(ipv4) => ipv4.is_loopback(),
            IpAddr::V6(ipv6) => ipv6.is_loopback(),
        }
    }
    
    /// Check if IP is routable (public)
    pub fn is_routable_ip(ip: &IpAddr) -> bool {
        !is_private_ip(ip) && !is_reserved_ip(ip)
    }
    
    /// Check if IP is in reserved ranges
    pub fn is_reserved_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Reserved ranges
                octets[0] == 0 ||     // 0.0.0.0/8
                octets[0] == 127 ||   // 127.0.0.0/8
                (octets[0] == 169 && octets[1] == 254) || // 169.254.0.0/16
                (octets[0] == 224) || // 224.0.0.0/4 multicast
                (octets[0] >= 240)    // 240.0.0.0/4 reserved
            }
            IpAddr::V6(_) => false, // Simplified for IPv6
        }
    }
    
    /// Extract IP from socket address
    pub fn extract_ip(addr: &SocketAddr) -> IpAddr {
        addr.ip()
    }
    
    /// Extract port from socket address
    pub fn extract_port(addr: &SocketAddr) -> u16 {
        addr.port()
    }
    
    /// Check if two IPs are in the same subnet
    pub fn same_subnet(ip1: &IpAddr, ip2: &IpAddr, prefix_len: u8) -> bool {
        match (ip1, ip2) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                if prefix_len > 32 { return false; }
                let mask = (!0u32).checked_shl(32 - prefix_len as u32).unwrap_or(0);
                (u32::from(*a) & mask) == (u32::from(*b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                if prefix_len > 128 { return false; }
                let a_bytes = a.octets();
                let b_bytes = b.octets();
                
                let full_bytes = prefix_len / 8;
                let remaining_bits = prefix_len % 8;
                
                // Check full bytes
                if a_bytes[..full_bytes as usize] != b_bytes[..full_bytes as usize] {
                    return false;
                }
                
                // Check remaining bits
                if remaining_bits > 0 && full_bytes < 16 {
                    let mask = (!0u8).checked_shl(8 - remaining_bits as u32).unwrap_or(0);
                    let idx = full_bytes as usize;
                    return (a_bytes[idx] & mask) == (b_bytes[idx] & mask);
                }
                
                true
            }
            _ => false, // Different IP versions
        }
    }
    
    /// Parse socket address from string
    pub fn parse_socket_addr(addr_str: &str) -> Result<SocketAddr> {
        addr_str.parse()
            .map_err(|e| PaliError::Parse(format!("Invalid socket address: {}", e)))
    }
    
    /// Format socket address for display
    pub fn format_socket_addr(addr: &SocketAddr) -> String {
        match addr {
            SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
            SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
        }
    }
}

/// File system utilities for secure file operations
pub mod file {
    use super::*;
    
    /// Ensure directory exists, create if necessary
    pub fn ensure_dir<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if !path.exists() {
            fs::create_dir_all(path)
                .map_err(|e| PaliError::Io(e))?;
            info!("Created directory: {}", path.display());
        }
        Ok(())
    }
    
    /// Get file size in bytes
    pub fn size<P: AsRef<Path>>(path: P) -> Result<u64> {
        let metadata = fs::metadata(path)
            .map_err(|e| PaliError::Io(e))?;
        Ok(metadata.len())
    }
    
    /// Check if file exists and is readable
    pub fn is_readable<P: AsRef<Path>>(path: P) -> bool {
        fs::metadata(path).is_ok()
    }
    
    /// Check if path is a directory
    pub fn is_directory<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref().is_dir()
    }
    
    /// Check if path is a file
    pub fn is_file<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref().is_file()
    }
    
    /// Backup file by copying to .bak extension
    pub fn backup<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            let timestamp = time::now();
            let backup_path = path.with_extension(
                format!("{}.{}.bak", 
                    path.extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or(""),
                    timestamp
                )
            );
            fs::copy(path, &backup_path)
                .map_err(|e| PaliError::Io(e))?;
            info!("Created backup: {}", backup_path.display());
        }
        Ok(())
    }
    
    /// Secure delete file by overwriting with random data
    pub fn secure_delete<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            let file_size = size(path)?;
            if file_size > 0 {
                // Overwrite with random data (3 passes)
                for _ in 0..3 {
                    let random_data = random::secure_bytes(file_size as usize);
                    fs::write(path, &random_data)
                        .map_err(|e| PaliError::Io(e))?;
                }
            }
            
            // Finally delete the file
            fs::remove_file(path)
                .map_err(|e| PaliError::Io(e))?;
            info!("Securely deleted file: {}", path.display());
        }
        Ok(())
    }
    
    /// Get directory listing with filtering
    pub fn list_directory<P: AsRef<Path>>(
        path: P, 
        extension_filter: Option<&str>
    ) -> Result<Vec<PathBuf>> {
        let mut entries = Vec::new();
        let dir = fs::read_dir(path)
            .map_err(|e| PaliError::Io(e))?;
        
        for entry in dir {
            let entry = entry.map_err(|e| PaliError::Io(e))?;
            let path = entry.path();
            
            if let Some(ext) = extension_filter {
                if path.extension().and_then(|s| s.to_str()) == Some(ext) {
                    entries.push(path);
                }
            } else {
                entries.push(path);
            }
        }
        
        entries.sort();
        Ok(entries)
    }
    
    /// Calculate directory size recursively
    pub fn directory_size<P: AsRef<Path>>(path: P) -> Result<u64> {
        let path = path.as_ref();
        let mut total_size = 0;
        
        if path.is_file() {
            return size(path);
        }
        
        let entries = fs::read_dir(path)
            .map_err(|e| PaliError::Io(e))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| PaliError::Io(e))?;
            let path = entry.path();
            
            if path.is_file() {
                total_size += size(&path)?;
            } else if path.is_dir() {
                total_size += directory_size(&path)?;
            }
        }
        
        Ok(total_size)
    }
    
    /// Clean old files from directory
    pub fn cleanup_old_files<P: AsRef<Path>>(
        path: P, 
        max_age_seconds: u64,
        pattern: Option<&str>
    ) -> Result<usize> {
        let path = path.as_ref();
        let mut cleaned_count = 0;
        let current_time = time::now();
        
        let entries = fs::read_dir(path)
            .map_err(|e| PaliError::Io(e))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| PaliError::Io(e))?;
            let file_path = entry.path();
            
            if !file_path.is_file() {
                continue;
            }
            
            // Check pattern if specified
            if let Some(pattern) = pattern {
                if let Some(filename) = file_path.file_name().and_then(|s| s.to_str()) {
                    if !filename.contains(pattern) {
                        continue;
                    }
                }
            }
            
            // Check file age
            let metadata = fs::metadata(&file_path)
                .map_err(|e| PaliError::Io(e))?;
            
            if let Ok(modified) = metadata.modified() {
                if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
                    let file_age = current_time - duration.as_secs();
                    if file_age > max_age_seconds {
                        if fs::remove_file(&file_path).is_ok() {
                            cleaned_count += 1;
                            debug!("Cleaned old file: {}", file_path.display());
                        }
                    }
                }
            }
        }
        
        Ok(cleaned_count)
    }
}

/// Cryptographic utilities for enhanced security operations
pub mod crypto {
    use super::*;
    
    /// Generate cryptographically secure random private key
    pub fn generate_private_key() -> Result<[u8; 32]> {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut thread_rng());
        Ok(secret_key.secret_bytes())
    }
    
    /// Derive public key from private key
    pub fn derive_public_key(private_key: &[u8; 32]) -> Result<[u8; 33]> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(private_key)
            .map_err(|e| PaliError::Crypto(format!("Invalid private key: {}", e)))?;
        
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        Ok(public_key.serialize())
    }
    
    /// Derive address from public key (Bitcoin-compatible)
    pub fn derive_address(public_key: &[u8]) -> Result<Address> {
        if public_key.len() != 33 && public_key.len() != 65 {
            return Err(PaliError::Crypto("Invalid public key length".to_string()));
        }
        
        // Hash160: RIPEMD160(SHA256(pubkey))
        let sha_hash = hash::sha256(public_key);
        let address_bytes = hash::ripemd160(&sha_hash);
        
        Ok(address_bytes)
    }
    
    /// Sign message with private key
    pub fn sign_message(private_key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(private_key)
            .map_err(|e| PaliError::Crypto(format!("Invalid private key: {}", e)))?;
        
        let message_hash = hash::double_sha256(message);
        let message = Message::from_digest_slice(&message_hash)
            .map_err(|e| PaliError::Crypto(format!("Invalid message: {}", e)))?;
        
        let signature = secp.sign_ecdsa(&message, &secret_key);
        Ok(signature.serialize_compact().to_vec())
    }
    
    /// Verify message signature
    pub fn verify_signature(
        public_key: &[u8], 
        message: &[u8], 
        signature: &[u8]
    ) -> Result<bool> {
        if signature.len() != 64 {
            return Ok(false);
        }
        
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_slice(public_key)
            .map_err(|e| PaliError::Crypto(format!("Invalid public key: {}", e)))?;
        
        let message_hash = hash::double_sha256(message);
        let message = Message::from_digest_slice(&message_hash)
            .map_err(|e| PaliError::Crypto(format!("Invalid message: {}", e)))?;
        
        let sig = Signature::from_compact(signature)
            .map_err(|e| PaliError::Crypto(format!("Invalid signature: {}", e)))?;
        
        Ok(secp.verify_ecdsa(&message, &sig, &pubkey).is_ok())
    }
    
    /// Generate deterministic keypair from seed
    pub fn keypair_from_seed(seed: &[u8]) -> Result<([u8; 32], [u8; 33])> {
        if seed.len() < 32 {
            return Err(PaliError::Crypto("Seed must be at least 32 bytes".to_string()));
        }
        
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&seed[..32]);
        
        // Ensure key is valid for secp256k1
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&private_key)
            .map_err(|e| PaliError::Crypto(format!("Invalid seed for key generation: {}", e)))?;
        
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        Ok((secret_key.secret_bytes(), public_key.serialize()))
    }
    
    /// Calculate checksum for data integrity
    pub fn checksum(data: &[u8]) -> [u8; 4] {
        let hash = hash::double_sha256(data);
        [hash[0], hash[1], hash[2], hash[3]]
    }
    
    /// Verify checksum
    pub fn verify_checksum(data: &[u8], expected_checksum: &[u8; 4]) -> bool {
        let calculated = checksum(data);
        calculated == *expected_checksum
    }
    
    /// Generate secure salt for password hashing
    pub fn generate_salt(length: usize) -> Vec<u8> {
        random::secure_bytes(length.max(16)) // Minimum 16 bytes
    }
    
    /// Derive key using PBKDF2
    pub fn pbkdf2_derive_key(
        password: &[u8], 
        salt: &[u8], 
        iterations: u32, 
        key_length: usize
    ) -> Vec<u8> {
        use pbkdf2::pbkdf2_hmac_array;
        use sha2::Sha256;
        
        let mut key = vec![0u8; key_length];
        pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
        key
    }
}

/// Monitoring and statistics utilities
pub mod monitoring {
    use super::*;
    
    /// System performance metrics
    #[derive(Debug, Clone)]
    pub struct SystemMetrics {
        pub cpu_usage: f64,
        pub memory_usage: u64,
        pub disk_usage: u64,
        pub network_in: u64,
        pub network_out: u64,
        pub timestamp: u64,
    }
    
    /// Blockchain metrics
    #[derive(Debug, Clone)]
    pub struct BlockchainMetrics {
        pub block_height: u64,
        pub transaction_count: u64,
        pub peer_count: usize,
        pub hashrate: f64,
        pub difficulty: u32,
        pub mempool_size: usize,
        pub sync_progress: f64,
        pub last_block_time: u64,
    }
    
    /// Update global transaction counter
    pub fn increment_tx_counter() -> u64 {
        TX_COUNTER.fetch_add(1, Ordering::Relaxed)
    }
    
    /// Update global block counter
    pub fn increment_block_counter() -> u64 {
        BLOCK_COUNTER.fetch_add(1, Ordering::Relaxed)
    }
    
    /// Update global peer counter
    pub fn update_peer_counter(count: u64) {
        PEER_COUNTER.store(count, Ordering::Relaxed);
    }
    
    /// Get current counters
    pub fn get_counters() -> (u64, u64, u64) {
        (
            TX_COUNTER.load(Ordering::Relaxed),
            BLOCK_COUNTER.load(Ordering::Relaxed),
            PEER_COUNTER.load(Ordering::Relaxed),
        )
    }
    
    /// Calculate average block time
    pub fn calculate_avg_block_time(block_times: &[u64]) -> f64 {
        if block_times.len() < 2 {
            return 0.0;
        }
        
        let total_time: u64 = block_times.windows(2)
            .map(|w| w[1].saturating_sub(w[0]))
            .sum();
        
        total_time as f64 / (block_times.len() - 1) as f64
    }
    
    /// Format hashrate for display
    pub fn format_hashrate(hashrate: f64) -> String {
        const UNITS: &[&str] = &["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s"];
        let mut rate = hashrate;
        let mut unit_index = 0;
        
        while rate >= 1000.0 && unit_index < UNITS.len() - 1 {
            rate /= 1000.0;
            unit_index += 1;
        }
        
        format!("{:.2} {}", rate, UNITS[unit_index])
    }
    
    /// Log system health status
    pub fn log_health_status(metrics: &BlockchainMetrics) {
        info!("Blockchain Health - Height: {}, Peers: {}, Hashrate: {}, Mempool: {}",
            metrics.block_height,
            metrics.peer_count,
            format_hashrate(metrics.hashrate),
            metrics.mempool_size
        );
    }
}

/// Configuration utilities for managing settings
pub mod config {
    use super::*;
    use serde_json;
    
    /// Validate configuration parameters
    pub fn validate_network_config(port: u16, max_peers: usize) -> Result<()> {
        if !validation::is_valid_port(port) {
            return Err(PaliError::Config("Invalid network port".to_string()));
        }
        
        if max_peers == 0 || max_peers > 10000 {
            return Err(PaliError::Config("Invalid max peers count".to_string()));
        }
        
        Ok(())
    }
    
    /// Validate mining configuration
    pub fn validate_mining_config(difficulty: u32, threads: u32) -> Result<()> {
        if !validation::is_valid_difficulty(difficulty) {
            return Err(PaliError::Config("Invalid mining difficulty".to_string()));
        }
        
        if threads == 0 || threads > 256 {
            return Err(PaliError::Config("Invalid thread count".to_string()));
        }
        
        Ok(())
    }
    
    /// Load JSON configuration from file
    pub fn load_json_config<T, P>(path: P) -> Result<T> 
    where
        T: serde::de::DeserializeOwned,
        P: AsRef<Path>,
    {
        let content = fs::read_to_string(path)
            .map_err(|e| PaliError::Config(format!("Failed to read config: {}", e)))?;
        
        serde_json::from_str(&content)
            .map_err(|e| PaliError::Config(format!("Failed to parse config: {}", e)))
    }
    
    /// Save JSON configuration to file
    pub fn save_json_config<T, P>(config: &T, path: P) -> Result<()>
    where
        T: serde::Serialize,
        P: AsRef<Path>,
    {
        let content = serde_json::to_string_pretty(config)
            .map_err(|e| PaliError::Config(format!("Failed to serialize config: {}", e)))?;
        
        fs::write(path, content)
            .map_err(|e| PaliError::Config(format!("Failed to write config: {}", e)))?;
        
        Ok(())
    }
}

/// Testing utilities for development and validation
#[cfg(test)]
pub mod testing {
    use super::*;
    
    /// Generate test private key (deterministic for testing)
    pub fn test_private_key(seed: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        let seed_bytes = seed.to_be_bytes();
        for i in 0..4 {
            key[i*8..(i+1)*8].copy_from_slice(&seed_bytes);
        }
        key
    }
    
    /// Generate test address
    pub fn test_address(seed: u64) -> Address {
        let mut addr = [0u8; 20];
        let seed_bytes = seed.to_be_bytes();
        for i in 0..2 {
            addr[i*8..(i+1)*8].copy_from_slice(&seed_bytes);
        }
        addr[16..20].copy_from_slice(&seed_bytes[4..8]);
        addr
    }
    
    /// Generate test hash
    pub fn test_hash(seed: u64) -> Hash {
        let mut hash = [0u8; 32];
        let seed_bytes = seed.to_be_bytes();
        for i in 0..4 {
            hash[i*8..(i+1)*8].copy_from_slice(&seed_bytes);
        }
        hash
    }
    
    /// Create temporary directory for testing
    pub fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("pali_test_{}", random::nonce()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_functions() {
        let data = b"test data for pali coin";
        
        // Test single SHA256
        let hash1 = hash::sha256(data);
        let hash2 = hash::sha256(data);
        assert_eq!(hash1, hash2); // Same input = same output
        
        // Test double SHA256
        let double_hash = hash::double_sha256(data);
        assert_ne!(hash1, double_hash); // Single vs double should differ
        
        // Test RIPEMD160
        let ripemd = hash::ripemd160(data);
        assert_eq!(ripemd.len(), 20);
        
        // Test hash160
        let hash160 = hash::hash160(data);
        assert_eq!(hash160.len(), 20);
    }

    #[test]
    fn test_merkle_root() {
        let hashes = vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        ];
        
        let root = hash::merkle_root(&hashes);
        assert_ne!(root, [0u8; 32]); // Should produce non-zero root
        
        // Test with single hash
        let single_root = hash::merkle_root(&hashes[0..1]);
        assert_eq!(single_root, hashes[0]);
        
        // Test with empty
        let empty_root = hash::merkle_root(&[]);
        assert_eq!(empty_root, [0u8; 32]);
    }

    #[test]
    fn test_encoding_functions() {
        let data = b"test encoding data";
        
        // Test hex encoding/decoding
        let hex = encoding::to_hex(data);
        let decoded = encoding::from_hex(&hex).unwrap();
        assert_eq!(data, decoded.as_slice());
        
        // Test base64 encoding/decoding
        let base64 = encoding::to_base64(data);
        let decoded_b64 = encoding::from_base64(&base64).unwrap();
        assert_eq!(data, decoded_b64.as_slice());
        
        // Test base58 encoding/decoding
        let base58 = encoding::to_base58(data);
        let decoded_b58 = encoding::from_base58(&base58).unwrap();
        assert_eq!(data, decoded_b58.as_slice());
    }

    #[test]
    fn test_validation_functions() {
        // Test difficulty validation
        let easy_hash = [0u8; 32]; // All zeros
        assert!(validation::meets_difficulty(&easy_hash, 256));
        
        let hard_hash = [255u8; 32]; // All ones
        assert!(!validation::meets_difficulty(&hard_hash, 1));
        
        // Test amount validation
        assert!(validation::is_valid_amount(1000));
        assert!(!validation::is_valid_amount(0));
        assert!(!validation::is_valid_amount(MAX_MONEY_SUPPLY + 1));
        
        // Test fee validation
        assert!(validation::is_valid_fee(MIN_TX_FEE, 1000000));
        assert!(!validation::is_valid_fee(0, 1000000));
        assert!(!validation::is_valid_fee(1000000, 1000)); // Fee > amount
    }

    #[test]
    fn test_time_functions() {
        let now = time::now();
        assert!(now > 0);
        
        let formatted = time::format_timestamp(now);
        assert!(formatted.contains("UTC"));
        
        let iso = time::format_iso8601(now);
        assert!(iso.contains("T"));
        
        // Test validation
        assert!(time::is_valid_block_timestamp(now, 7200));
        assert!(!time::is_valid_block_timestamp(now + 10000, 7200));
    }

    #[test]
    fn test_network_functions() {
        use std::net::Ipv4Addr;
        
        let private_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(network::is_private_ip(&private_ip));
        
        let public_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!network::is_private_ip(&public_ip));
        assert!(network::is_routable_ip(&public_ip));
        
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(network::is_private_ip(&localhost));
    }

    #[test]
    fn test_math_functions() {
        // Test difficulty adjustment
        let new_diff = math::calculate_difficulty_adjustment(20, 1200, 600);
        assert!(new_diff > 20); // Should increase difficulty
        
        let new_diff2 = math::calculate_difficulty_adjustment(20, 300, 600);
        assert!(new_diff2 < 20); // Should decrease difficulty
        
        // Test compound interest
        let result = math::compound_interest(1000, 0.1, 2);
        assert_eq!(result, 1210); // 1000 * 1.1^2 = 1210
        
        // Test percentage
        let pct = math::percentage(25, 100);
        assert_eq!(pct, 25.0);
        
        // Test conversion functions
        let pali = math::satoshis_to_pali(100_000_000);
        assert_eq!(pali, 1.0);
        
        let satoshis = math::pali_to_satoshis(1.0);
        assert_eq!(satoshis, 100_000_000);
    }

    #[test]
    fn test_crypto_functions() {
        // Test key generation
        let private_key = crypto::generate_private_key().unwrap();
        assert_eq!(private_key.len(), 32);
        
        // Test public key derivation
        let public_key = crypto::derive_public_key(&private_key).unwrap();
        assert_eq!(public_key.len(), 33);
        
        // Test address derivation
        let address = crypto::derive_address(&public_key).unwrap();
        assert_eq!(address.len(), 20);
        
        // Test signing and verification
        let message = b"test message";
        let signature = crypto::sign_message(&private_key, message).unwrap();
        let is_valid = crypto::verify_signature(&public_key, message, &signature).unwrap();
        assert!(is_valid);
        
        // Test checksum
        let data = b"test data";
        let checksum = crypto::checksum(data);
        assert!(crypto::verify_checksum(data, &checksum));
    }

    #[test]
    fn test_random_functions() {
        // Test different random generators
        let bytes1 = random::secure_bytes(32);
        let bytes2 = random::secure_bytes(32);
        assert_ne!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
        
        let hash1 = random::hash();
        let hash2 = random::hash();
        assert_ne!(hash1, hash2);
        
        let addr1 = random::address();
        let addr2 = random::address();
        assert_ne!(addr1, addr2);
        
        let nonce1 = random::nonce();
        let nonce2 = random::nonce();
        assert_ne!(nonce1, nonce2);
        
        let string1 = random::string(10);
        let string2 = random::string(10);
        assert_ne!(string1, string2);
        assert_eq!(string1.len(), 10);
    }

    #[test]
    fn test_monitoring_functions() {
        // Test counter functions
        let initial_tx = monitoring::increment_tx_counter();
        let next_tx = monitoring::increment_tx_counter();
        assert_eq!(next_tx, initial_tx + 1);
        
        monitoring::update_peer_counter(42);
        let (_, _, peer_count) = monitoring::get_counters();
        assert_eq!(peer_count, 42);
        
        // Test hashrate formatting
        let formatted = monitoring::format_hashrate(1500.0);
        assert!(formatted.contains("KH/s"));
        
        let formatted_large = monitoring::format_hashrate(1_500_000.0);
        assert!(formatted_large.contains("MH/s"));
    }
}
