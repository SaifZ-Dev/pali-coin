// src/lib.rs - Pali Coin Cryptocurrency Library
//! # Pali Coin
//! 
//! A secure, modern cryptocurrency implementation in Rust featuring:
//! - ECDSA transaction signatures with recovery
//! - Proof-of-work mining with dynamic difficulty adjustment
//! - UTXO-based transaction model
//! - Economic incentives and reward halving
//! - DDoS protection and rate limiting
//! - Zero-knowledge proof support
//! - BIP39 wallet compatibility

pub mod blockchain;
pub mod types;
// pub mod network;  // TODO: Fix compilation errors
pub mod security;
// pub mod wallet;   // TODO: Fix compilation errors  
// pub mod mining;   // TODO: Fix compilation errors
// pub mod p2p;      // TODO: Fix compilation errors
// pub mod config;   // TODO: Fix compilation errors
// pub mod utils;    // TODO: Fix compilation errors
pub mod error;

// Re-export main types for easy access
// Re-export main types for easy access
pub use blockchain::Blockchain;
pub use types::{Block, Transaction, Hash, Address, BlockHeader};
// pub use network::{SecureNetworkClient, MessagePayload, NetworkMessage};
// pub use security::{SecurityManager, RateLimitConfig, MessageSecurity};
pub use security::SecurityManager;
// pub use wallet::{Wallet, WalletConfig, KeyPair};
// pub use mining::{Miner, MiningConfig};
pub use error::{PaliError, Result};
// pub use config::PaliConfig;

/// Pali Coin version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Network constants
pub mod constants {
    /// Default network port
    pub const DEFAULT_PORT: u16 = 8333;
    
    /// Chain ID for mainnet
    pub const MAINNET_CHAIN_ID: u64 = 1;
    
    /// Chain ID for testnet
    pub const TESTNET_CHAIN_ID: u64 = 2;
    
    /// Maximum block size in bytes
    pub const MAX_BLOCK_SIZE: usize = 4_000_000; // 4MB
    
    /// Maximum transaction size in bytes
    pub const MAX_TRANSACTION_SIZE: usize = 100_000; // 100KB
    
    /// Target block time in seconds
    pub const TARGET_BLOCK_TIME: u64 = 600; // 10 minutes
    
    /// Difficulty adjustment period in blocks
    pub const DIFFICULTY_ADJUSTMENT_PERIOD: u64 = 10;
    
    /// Reward halving period in blocks
    pub const REWARD_HALVING_PERIOD: u64 = 210_000;
    
    /// Initial mining reward
    pub const INITIAL_MINING_REWARD: u64 = 5_000_000; // 5 PALI with 6 decimal places
    
    /// Maximum supply (21 million coins with 6 decimal places)
    pub const MAX_SUPPLY: u64 = 21_000_000_000_000;
    
    /// Minimum transaction fee
    pub const MIN_TRANSACTION_FEE: u64 = 1000; // 0.001 PALI
}

/// Initialize logging for Pali Coin applications
pub fn init_logging() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
}

/// Initialize logging with custom level
pub fn init_logging_with_level(level: log::LevelFilter) {
    env_logger::Builder::from_default_env()
        .filter_level(level)
        .init();
}

/// Format amount in PALI coins for display
pub fn format_amount(amount: u64) -> String {
    let pali = amount / 1_000_000;
    let micropali = amount % 1_000_000;
    format!("{}.{:06} PALI", pali, micropali)
}

/// Parse amount from string (e.g., "1.5" -> 1500000)
pub fn parse_amount(amount_str: &str) -> Result<u64> {
    let parts: Vec<&str> = amount_str.split('.').collect();
    
    if parts.len() > 2 {
        return Err(PaliError::InvalidAmount("Too many decimal points".to_string()));
    }
    
    let whole_part: u64 = parts[0].parse()
        .map_err(|_| PaliError::InvalidAmount("Invalid whole number".to_string()))?;
    
    let fractional_part = if parts.len() == 2 {
        let frac_str = format!("{:0<6}", parts[1]); // Pad with zeros
        if frac_str.len() > 6 {
            return Err(PaliError::InvalidAmount("Too many decimal places".to_string()));
        }
        frac_str[..6].parse()
            .map_err(|_| PaliError::InvalidAmount("Invalid decimal number".to_string()))?
    } else {
        0
    };
    
    Ok(whole_part * 1_000_000 + fractional_part)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(1_000_000), "1.000000 PALI");
        assert_eq!(format_amount(1_500_000), "1.500000 PALI");
        assert_eq!(format_amount(500_000), "0.500000 PALI");
    }

    #[test]
    fn test_parse_amount() {
        assert_eq!(parse_amount("1").unwrap(), 1_000_000);
        assert_eq!(parse_amount("1.5").unwrap(), 1_500_000);
        assert_eq!(parse_amount("0.5").unwrap(), 500_000);
        assert_eq!(parse_amount("1.000001").unwrap(), 1_000_001);
    }

    #[test]
    fn test_parse_amount_errors() {
        assert!(parse_amount("1.2.3").is_err());
        assert!(parse_amount("abc").is_err());
        assert!(parse_amount("1.1234567").is_err()); // Too many decimals
    }
}
