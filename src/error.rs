// src/error.rs - Comprehensive error handling for Pali Coin
use std::fmt;
use thiserror::Error;

/// Result type alias for Pali Coin operations
pub type Result<T> = std::result::Result<T, PaliError>;

/// Main error type for Pali Coin operations
#[derive(Error, Debug)]
pub enum PaliError {
    #[error("Blockchain error: {0}")]
    Blockchain(String),
    
    #[error("Transaction error: {0}")]
    Transaction(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Wallet error: {0}")]
    Wallet(String),
    
    #[error("Mining error: {0}")]
    Mining(String),
    
    #[error("Security error: {0}")]
    Security(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
    
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    #[error("Insufficient funds: {0}")]
    InsufficientFunds(String),
    
    #[error("Block validation failed: {0}")]
    BlockValidation(String),
    
    #[error("Transaction validation failed: {0}")]
    TransactionValidation(String),
    
    #[error("Proof of work validation failed: {0}")]
    ProofOfWork(String),
    
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
    
    #[error("Connection timeout: {0}")]
    Timeout(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Database error: {0}")]
    RocksDb(#[from] rocksdb::Error),
    
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
    
    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl PaliError {
    /// Create a new blockchain error
    pub fn blockchain<S: Into<String>>(msg: S) -> Self {
        PaliError::Blockchain(msg.into())
    }
    
    /// Create a new transaction error
    pub fn transaction<S: Into<String>>(msg: S) -> Self {
        PaliError::Transaction(msg.into())
    }
    
    /// Create a new network error
    pub fn network<S: Into<String>>(msg: S) -> Self {
        PaliError::Network(msg.into())
    }
    
    /// Create a new crypto error
    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        PaliError::Crypto(msg.into())
    }
    
    /// Create a new wallet error
    pub fn wallet<S: Into<String>>(msg: S) -> Self {
        PaliError::Wallet(msg.into())
    }
    
    /// Create a new mining error
    pub fn mining<S: Into<String>>(msg: S) -> Self {
        PaliError::Mining(msg.into())
    }
    
    /// Create a new security error
    pub fn security<S: Into<String>>(msg: S) -> Self {
        PaliError::Security(msg.into())
    }
    
    /// Check if error is related to network issues
    pub fn is_network_error(&self) -> bool {
        matches!(self, PaliError::Network(_) | PaliError::Timeout(_))
    }
    
    /// Check if error is related to validation
    pub fn is_validation_error(&self) -> bool {
        matches!(
            self,
            PaliError::BlockValidation(_) |
            PaliError::TransactionValidation(_) |
            PaliError::ProofOfWork(_) |
            PaliError::InvalidSignature(_)
        )
    }
    
    /// Check if error is related to security
    pub fn is_security_error(&self) -> bool {
        matches!(self, PaliError::Security(_) | PaliError::RateLimit(_))
    }
    
    /// Get error category for logging
    pub fn category(&self) -> &'static str {
        match self {
            PaliError::Blockchain(_) => "blockchain",
            PaliError::Transaction(_) => "transaction",
            PaliError::Network(_) => "network",
            PaliError::Crypto(_) => "crypto",
            PaliError::Wallet(_) => "wallet",
            PaliError::Mining(_) => "mining",
            PaliError::Security(_) => "security",
            PaliError::Config(_) => "config",
            PaliError::Database(_) => "database",
            PaliError::Serialization(_) => "serialization",
            PaliError::InvalidAmount(_) => "validation",
            PaliError::InvalidAddress(_) => "validation",
            PaliError::InvalidSignature(_) => "validation",
            PaliError::InsufficientFunds(_) => "validation",
            PaliError::BlockValidation(_) => "validation",
            PaliError::TransactionValidation(_) => "validation",
            PaliError::ProofOfWork(_) => "validation",
            PaliError::RateLimit(_) => "security",
            PaliError::Timeout(_) => "network",
            PaliError::Io(_) => "io",
            PaliError::Json(_) => "serialization",
            PaliError::RocksDb(_) => "database",
            PaliError::Secp256k1(_) => "crypto",
            PaliError::HexDecode(_) => "serialization",
            PaliError::Parse(_) => "parse",
            PaliError::Unknown(_) => "unknown",
        }
    }
}

/// Convert various error types to PaliError
impl From<Box<dyn std::error::Error + Send + Sync>> for PaliError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        PaliError::Unknown(err.to_string())
    }
}

impl From<String> for PaliError {
    fn from(err: String) -> Self {
        PaliError::Unknown(err)
    }
}

impl From<&str> for PaliError {
    fn from(err: &str) -> Self {
        PaliError::Unknown(err.to_string())
    }
}

/// Helper macro for creating errors with context
#[macro_export]
macro_rules! pali_error {
    ($variant:ident, $msg:expr) => {
        PaliError::$variant($msg.to_string())
    };
    ($variant:ident, $fmt:expr, $($arg:tt)*) => {
        PaliError::$variant(format!($fmt, $($arg)*))
    };
}

/// Helper macro for creating results
#[macro_export]
macro_rules! pali_result {
    ($expr:expr) => {
        $expr.map_err(|e| PaliError::Unknown(e.to_string()))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        let blockchain_err = PaliError::blockchain("test");
        assert_eq!(blockchain_err.category(), "blockchain");
        
        let network_err = PaliError::network("test");
        assert!(network_err.is_network_error());
        
        let validation_err = PaliError::BlockValidation("test".to_string());
        assert!(validation_err.is_validation_error());
    }

    #[test]
    fn test_error_conversion() {
        let string_err: PaliError = "test error".into();
        assert!(matches!(string_err, PaliError::Unknown(_)));
        
        let owned_string_err: PaliError = "test error".to_string().into();
        assert!(matches!(owned_string_err, PaliError::Unknown(_)));
    }
}
