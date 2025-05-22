// src/utils.rs - Utility functions for Pali Coin
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use crate::error::{PaliError, Result};
use crate::types::{Hash, Address};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::{Rng, RngCore};

/// Hash utilities
pub mod hash {
    use super::*;
    
    /// Calculate SHA-256 hash
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
    
    /// Calculate merkle root from a list of hashes
    pub fn merkle_root(hashes: &[Hash]) -> Hash {
        if hashes.is_empty() {
            return [0; 32];
        }
        
        let mut current_level = hashes.to_vec();
        
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    [chunk[0], chunk[1]].concat()
                } else {
                    // If odd number, duplicate the last hash
                    [chunk[0], chunk[0]].concat()
                };
                
                next_level.push(double_sha256(&combined));
            }
            
            current_level = next_level;
        }
        
        current_level[0]
    }
}

/// Time utilities
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
    
    /// Convert timestamp to human-readable format
    pub fn format_timestamp(timestamp: u64) -> String {
        use chrono::{DateTime, Utc, TimeZone};
        
        let dt = Utc.timestamp_opt(timestamp as i64, 0)
            .single()
            .unwrap_or_else(|| Utc::now());
        
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }
    
    /// Check if timestamp is within acceptable range
    pub fn is_valid_timestamp(timestamp: u64, max_drift_seconds: u64) -> bool {
        let current = now();
        let max_future = current + max_drift_seconds;
        let max_past = current.saturating_sub(max_drift_seconds);
        
        timestamp >= max_past && timestamp <= max_future
    }
}

/// Encoding utilities
pub mod encoding {
    use super::*;
    use base64::{Engine as _, engine::general_purpose};
    
    /// Encode bytes to hexadecimal string
    pub fn to_hex(data: &[u8]) -> String {
        hex::encode(data)
    }
    
    /// Decode hexadecimal string to bytes
    pub fn from_hex(hex_str: &str) -> Result<Vec<u8>> {
        hex::decode(hex_str).map_err(|e| PaliError::Parse(format!("Invalid hex: {}", e)))
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
    
    /// Encode address to string representation
    pub fn address_to_string(address: &Address) -> String {
        to_hex(address)
    }
    
    /// Decode string to address
    pub fn string_to_address(address_str: &str) -> Result<Address> {
        let bytes = from_hex(address_str)?;
        if bytes.len() != 20 {
            return Err(PaliError::InvalidAddress("Address must be 20 bytes".to_string()));
        }
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&bytes);
        Ok(address)
    }
    
    /// Validate address string format
    pub fn is_valid_address_string(address_str: &str) -> bool {
        address_str.len() == 40 && 
        address_str.chars().all(|c| c.is_ascii_hexdigit())
    }
}

/// Validation utilities
pub mod validation {
    use super::*;
    
    /// Validate proof of work meets difficulty requirement
    pub fn meets_difficulty(hash: &Hash, difficulty: u32) -> bool {
        // Count leading zero bits
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
    
    /// Validate transaction amount
    pub fn is_valid_amount(amount: u64) -> bool {
        amount > 0 && amount <= crate::constants::MAX_SUPPLY
    }
    
    /// Validate transaction fee
    pub fn is_valid_fee(fee: u64, amount: u64) -> bool {
        fee >= crate::constants::MIN_TRANSACTION_FEE && 
        fee <= amount / 10 // Max 10% fee
    }
    
    /// Validate block size
    pub fn is_valid_block_size(block_size: usize) -> bool {
        block_size > 0 && block_size <= crate::constants::MAX_BLOCK_SIZE
    }
    
    /// Validate network port
    pub fn is_valid_port(port: u16) -> bool {
        port >= 1024 && port <= 65535
    }
}

/// Random utilities
pub mod random {
    use super::*;
    
    /// Generate random bytes
    pub fn bytes(len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }
    
    /// Generate random hash
    pub fn hash() -> Hash {
        let mut rng = rand::thread_rng();
        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        hash
    }
    
    /// Generate random address
    pub fn address() -> Address {
        let mut rng = rand::thread_rng();
        let mut addr = [0u8; 20];
        rng.fill_bytes(&mut addr);
        addr
    }
    
    /// Generate random nonce
    pub fn nonce() -> u64 {
        rand::thread_rng().gen()
    }
    
    /// Generate random string of given length
    pub fn string(len: usize) -> String {
        use rand::distributions::{Alphanumeric, DistString};
        Alphanumeric.sample_string(&mut rand::thread_rng(), len)
    }
}

/// Mathematical utilities
pub mod math {
    /// Calculate difficulty adjustment
    pub fn calculate_difficulty_adjustment(
        current_difficulty: u32,
        actual_time: u64,
        target_time: u64,
    ) -> u32 {
        // Limit adjustment to ±25% per period
        let max_adjustment_factor = 4;
        let min_adjustment_factor = 1;
        
        let adjustment_factor = if actual_time < target_time {
            // Blocks came too fast, increase difficulty
            (target_time * max_adjustment_factor).min(actual_time * max_adjustment_factor) / actual_time
        } else {
            // Blocks came too slow, decrease difficulty
            (actual_time * min_adjustment_factor).max(target_time * min_adjustment_factor) / target_time
        };
        
        let new_difficulty = (current_difficulty as u64 * target_time / actual_time) as u32;
        
        // Ensure difficulty doesn't change too drastically
        let max_new_difficulty = current_difficulty * max_adjustment_factor;
        let min_new_difficulty = current_difficulty / max_adjustment_factor;
        
        new_difficulty.clamp(min_new_difficulty, max_new_difficulty).max(1)
    }
    
    /// Calculate compound interest for staking rewards
    pub fn compound_interest(principal: u64, rate: f64, periods: u64) -> u64 {
        let result = principal as f64 * (1.0 + rate).powi(periods as i32);
        result as u64
    }
    
    /// Calculate percentage
    pub fn percentage(value: u64, total: u64) -> f64 {
        if total == 0 {
            0.0
        } else {
            (value as f64 / total as f64) * 100.0
        }
    }
}

/// Network utilities
pub mod network {
    use std::net::{IpAddr, SocketAddr};
    
    /// Check if IP address is in private range
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_multicast()
            }
        }
    }
    
    /// Extract IP from socket address
    pub fn extract_ip(addr: &SocketAddr) -> IpAddr {
        addr.ip()
    }
    
    /// Check if address is localhost
    pub fn is_localhost(addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(ipv4) => ipv4.is_loopback(),
            IpAddr::V6(ipv6) => ipv6.is_loopback(),
        }
    }
}

/// File utilities
pub mod file {
    use std::fs;
    use std::path::Path;
    use super::*;
    
    /// Ensure directory exists
    pub fn ensure_dir<P: AsRef<Path>>(path: P) -> Result<()> {
        if !path.as_ref().exists() {
            fs::create_dir_all(path)
                .map_err(|e| PaliError::Io(e))?;
        }
        Ok(())
    }
    
    /// Get file size
    pub fn size<P: AsRef<Path>>(path: P) -> Result<u64> {
        let metadata = fs::metadata(path)
            .map_err(|e| PaliError::Io(e))?;
        Ok(metadata.len())
    }
    
    /// Check if file exists and is readable
    pub fn is_readable<P: AsRef<Path>>(path: P) -> bool {
        fs::metadata(path).is_ok()
    }
    
    /// Backup file by copying to .bak extension
    pub fn backup<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            let backup_path = path.with_extension(
                format!("{}.bak", 
                    path.extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                )
            );
            fs::copy(path, backup_path)
                .map_err(|e| PaliError::Io(e))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_functions() {
        let data = b"hello world";
        let hash1 = hash::sha256(data);
        let hash2 = hash::sha256(data);
        assert_eq!(hash1, hash2); // Same input should produce same hash
        
        let double_hash = hash::double_sha256(data);
        assert_ne!(hash1, double_hash); // Single and double hash should differ
    }

    #[test]
    fn test_merkle_root() {
        let hashes = vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        ];
        
        let root = hash::merkle_root(&hashes);
        assert_ne!(root, [0u8; 32]); // Should produce non-zero root
    }

    #[test]
    fn test_encoding() {
        let data = b"test data";
        let hex = encoding::to_hex(data);
        let decoded = encoding::from_hex(&hex).unwrap();
        assert_eq!(data, decoded.as_slice());
        
        let base64 = encoding::to_base64(data);
        let decoded_b64 = encoding::from_base64(&base64).unwrap();
        assert_eq!(data, decoded_b64.as_slice());
    }

    #[test]
    fn test_validation() {
        // Test difficulty validation
        let easy_hash = [0u8; 32]; // All zeros - meets any difficulty
        assert!(validation::meets_difficulty(&easy_hash, 256));
        
        let hard_hash = [255u8; 32]; // All ones - meets no difficulty
        assert!(!validation::meets_difficulty(&hard_hash, 1));
        
        // Test amount validation
        assert!(validation::is_valid_amount(1000));
        assert!(!validation::is_valid_amount(0));
        assert!(!validation::is_valid_amount(u64::MAX));
    }

    #[test]
    fn test_time_functions() {
        let now = time::now();
        assert!(now > 0);
        
        let formatted = time::format_timestamp(now);
        assert!(formatted.contains("UTC"));
        
        assert!(time::is_valid_timestamp(now, 300)); // 5 minutes drift
        assert!(!time::is_valid_timestamp(now + 3600, 300)); // 1 hour in future
    }

    #[test]
    fn test_random_functions() {
        let bytes1 = random::bytes(32);
        let bytes2 = random::bytes(32);
        assert_ne!(bytes1, bytes2); // Should be different
        assert_eq!(bytes1.len(), 32);
        
        let hash1 = random::hash();
        let hash2 = random::hash();
        assert_ne!(hash1, hash2);
        
        let addr1 = random::address();
        let addr2 = random::address();
        assert_ne!(addr1, addr2);
    }
}
