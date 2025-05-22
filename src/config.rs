// src/config.rs - Configuration management for Pali Coin
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use crate::error::{PaliError, Result};
use crate::constants::*;

/// Main configuration for Pali Coin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaliConfig {
    /// Network configuration
    pub network: NetworkConfig,
    
    /// Blockchain configuration
    pub blockchain: BlockchainConfig,
    
    /// Mining configuration
    pub mining: MiningConfig,
    
    /// Security configuration
    pub security: SecurityConfig,
    
    /// Wallet configuration
    pub wallet: WalletConfig,
    
    /// Database configuration
    pub database: DatabaseConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Port to listen on
    pub port: u16,
    
    /// Maximum number of peer connections
    pub max_peers: u32,
    
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    
    /// Enable P2P networking
    pub enable_p2p: bool,
    
    /// Bootstrap nodes for P2P network
    pub bootstrap_nodes: Vec<String>,
    
    /// Network magic bytes
    pub network_magic: u32,
    
    /// Chain ID
    pub chain_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    /// Data directory for blockchain storage
    pub data_dir: PathBuf,
    
    /// Target block time in seconds
    pub target_block_time: u64,
    
    /// Difficulty adjustment period
    pub difficulty_adjustment_period: u64,
    
    /// Maximum block size in bytes
    pub max_block_size: usize,
    
    /// Maximum transactions per block
    pub max_transactions_per_block: usize,
    
    /// Initial mining reward
    pub initial_mining_reward: u64,
    
    /// Reward halving period
    pub reward_halving_period: u64,
    
    /// Enable transaction indexing
    pub enable_transaction_index: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningConfig {
    /// Enable mining
    pub enabled: bool,
    
    /// Mining reward address
    pub reward_address: Option<String>,
    
    /// Number of mining threads
    pub threads: u32,
    
    /// Mining algorithm difficulty
    pub difficulty: u32,
    
    /// Maximum mining time per block in seconds
    pub max_mining_time: u64,
    
    /// Enable solo mining
    pub solo_mining: bool,
    
    /// Mining pool address (if not solo mining)
    pub pool_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable rate limiting
    pub rate_limiting: bool,
    
    /// Maximum requests per minute per IP
    pub max_requests_per_minute: u32,
    
    /// Maximum bandwidth per minute per IP (bytes)
    pub max_bandwidth_per_minute: u64,
    
    /// Maximum connections per IP
    pub max_connections_per_ip: u32,
    
    /// Ban duration in minutes
    pub ban_duration_minutes: u64,
    
    /// Enable DDoS protection
    pub ddos_protection: bool,
    
    /// Enable message validation
    pub message_validation: bool,
    
    /// Trusted node addresses (bypass some security checks)
    pub trusted_nodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Default wallet directory
    pub wallet_dir: PathBuf,
    
    /// Enable wallet encryption
    pub encryption_enabled: bool,
    
    /// Wallet backup interval in minutes
    pub backup_interval: u64,
    
    /// Number of wallet backups to keep
    pub backup_count: u32,
    
    /// Enable HD wallet features
    pub hd_wallet: bool,
    
    /// Default derivation path
    pub derivation_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database cache size in MB
    pub cache_size: u64,
    
    /// Enable database compression
    pub compression: bool,
    
    /// Database write buffer size in MB
    pub write_buffer_size: u64,
    
    /// Maximum number of open files
    pub max_open_files: i32,
    
    /// Enable database statistics
    pub enable_statistics: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (error, warn, info, debug, trace)
    pub level: String,
    
    /// Log to file
    pub log_to_file: bool,
    
    /// Log file path
    pub log_file: Option<PathBuf>,
    
    /// Maximum log file size in MB
    pub max_log_size: u64,
    
    /// Number of log files to keep
    pub log_file_count: u32,
    
    /// Enable colored output
    pub colored_output: bool,
}

impl Default for PaliConfig {
    fn default() -> Self {
        PaliConfig {
            network: NetworkConfig {
                port: DEFAULT_PORT,
                max_peers: 50,
                connection_timeout: 30,
                enable_p2p: true,
                bootstrap_nodes: vec![
                    "pali-node-1.example.com:8333".to_string(),
                    "pali-node-2.example.com:8333".to_string(),
                ],
                network_magic: 0xD9B4BEF9,
                chain_id: MAINNET_CHAIN_ID,
            },
            blockchain: BlockchainConfig {
                data_dir: PathBuf::from("data"),
                target_block_time: TARGET_BLOCK_TIME,
                difficulty_adjustment_period: DIFFICULTY_ADJUSTMENT_PERIOD,
                max_block_size: MAX_BLOCK_SIZE,
                max_transactions_per_block: 1000,
                initial_mining_reward: INITIAL_MINING_REWARD,
                reward_halving_period: REWARD_HALVING_PERIOD,
                enable_transaction_index: true,
            },
            mining: MiningConfig {
                enabled: false,
                reward_address: None,
                threads: num_cpus::get() as u32,
                difficulty: 20,
                max_mining_time: 300, // 5 minutes
                solo_mining: true,
                pool_address: None,
            },
            security: SecurityConfig {
                rate_limiting: true,
                max_requests_per_minute: 60,
                max_bandwidth_per_minute: 1_000_000, // 1MB
                max_connections_per_ip: 5,
                ban_duration_minutes: 15,
                ddos_protection: true,
                message_validation: true,
                trusted_nodes: Vec::new(),
            },
            wallet: WalletConfig {
                wallet_dir: PathBuf::from("wallets"),
                encryption_enabled: true,
                backup_interval: 60, // 1 hour
                backup_count: 5,
                hd_wallet: true,
                derivation_path: "m/44'/0'/0'".to_string(),
            },
            database: DatabaseConfig {
                cache_size: 256, // 256MB
                compression: true,
                write_buffer_size: 64, // 64MB
                max_open_files: 1000,
                enable_statistics: false,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                log_to_file: true,
                log_file: Some(PathBuf::from("logs/pali-coin.log")),
                max_log_size: 100, // 100MB
                log_file_count: 5,
                colored_output: true,
            },
        }
    }
}

impl PaliConfig {
    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| PaliError::config(format!("Failed to read config file: {}", e)))?;
        
        let config: PaliConfig = toml::from_str(&content)
            .map_err(|e| PaliError::config(format!("Failed to parse config file: {}", e)))?;
        
        config.validate()?;
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| PaliError::config(format!("Failed to serialize config: {}", e)))?;
        
        // Create directory if it doesn't exist
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)
                .map_err(|e| PaliError::config(format!("Failed to create config directory: {}", e)))?;
        }
        
        fs::write(path, content)
            .map_err(|e| PaliError::config(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }
    
    /// Load configuration from default locations
    pub fn load_default() -> Result<Self> {
        let config_paths = [
            "pali-coin.toml",
            "config/pali-coin.toml",
            dirs::config_dir().map(|d| d.join("pali-coin").join("config.toml")),
        ];
        
        for path_opt in &config_paths {
            if let Some(path) = path_opt {
                if path.exists() {
                    return Self::load_from_file(path);
                }
            }
        }
        
        // If no config file found, use default and save it
        let config = Self::default();
        if let Err(e) = config.save_to_file("pali-coin.toml") {
            log::warn!("Failed to save default config: {}", e);
        }
        
        Ok(config)
    }
    
    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        // Validate network configuration
        if self.network.port == 0 {
            return Err(PaliError::config("Network port cannot be zero"));
        }
        
        if self.network.max_peers == 0 {
            return Err(PaliError::config("Max peers must be greater than zero"));
        }
        
        if self.network.connection_timeout == 0 {
            return Err(PaliError::config("Connection timeout must be greater than zero"));
        }
        
        // Validate blockchain configuration
        if self.blockchain.target_block_time == 0 {
            return Err(PaliError::config("Target block time must be greater than zero"));
        }
        
        if self.blockchain.max_block_size == 0 {
            return Err(PaliError::config("Max block size must be greater than zero"));
        }
        
        if self.blockchain.max_transactions_per_block == 0 {
            return Err(PaliError::config("Max transactions per block must be greater than zero"));
        }
        
        // Validate mining configuration
        if self.mining.threads == 0 {
            return Err(PaliError::config("Mining threads must be greater than zero"));
        }
        
        if self.mining.difficulty == 0 {
            return Err(PaliError::config("Mining difficulty must be greater than zero"));
        }
        
        // Validate security configuration
        if self.security.max_requests_per_minute == 0 {
            return Err(PaliError::config("Max requests per minute must be greater than zero"));
        }
        
        if self.security.max_connections_per_ip == 0 {
            return Err(PaliError::config("Max connections per IP must be greater than zero"));
        }
        
        // Validate logging level
        match self.logging.level.as_str() {
            "error" | "warn" | "info" | "debug" | "trace" => {},
            _ => return Err(PaliError::config("Invalid log level")),
        }
        
        Ok(())
    }
    
    /// Get data directory, creating it if necessary
    pub fn get_data_dir(&self) -> Result<PathBuf> {
        let data_dir = &self.blockchain.data_dir;
        
        if !data_dir.exists() {
            fs::create_dir_all(data_dir)
                .map_err(|e| PaliError::config(format!("Failed to create data directory: {}", e)))?;
        }
        
        Ok(data_dir.clone())
    }
    
    /// Get wallet directory, creating it if necessary
    pub fn get_wallet_dir(&self) -> Result<PathBuf> {
        let wallet_dir = &self.wallet.wallet_dir;
        
        if !wallet_dir.exists() {
            fs::create_dir_all(wallet_dir)
                .map_err(|e| PaliError::config(format!("Failed to create wallet directory: {}", e)))?;
        }
        
        Ok(wallet_dir.clone())
    }
    
    /// Get log directory, creating it if necessary
    pub fn get_log_dir(&self) -> Result<Option<PathBuf>> {
        if let Some(log_file) = &self.logging.log_file {
            if let Some(log_dir) = log_file.parent() {
                if !log_dir.exists() {
                    fs::create_dir_all(log_dir)
                        .map_err(|e| PaliError::config(format!("Failed to create log directory: {}", e)))?;
                }
                return Ok(Some(log_dir.to_path_buf()));
            }
        }
        Ok(None)
    }
    
    /// Check if we're running in testnet mode
    pub fn is_testnet(&self) -> bool {
        self.network.chain_id == TESTNET_CHAIN_ID
    }
    
    /// Check if mining is enabled
    pub fn is_mining_enabled(&self) -> bool {
        self.mining.enabled && self.mining.reward_address.is_some()
    }
    
    /// Get network string for display
    pub fn network_name(&self) -> &'static str {
        match self.network.chain_id {
            MAINNET_CHAIN_ID => "mainnet",
            TESTNET_CHAIN_ID => "testnet",
            _ => "unknown",
        }
    }
    
    /// Merge configuration with command line arguments
    pub fn merge_with_args(&mut self, args: &ConfigArgs) {
        if let Some(port) = args.port {
            self.network.port = port;
        }
        
        if let Some(ref data_dir) = args.data_dir {
            self.blockchain.data_dir = PathBuf::from(data_dir);
        }
        
        if let Some(ref log_level) = args.log_level {
            self.logging.level = log_level.clone();
        }
        
        if args.enable_mining {
            self.mining.enabled = true;
        }
        
        if let Some(ref mining_address) = args.mining_address {
            self.mining.reward_address = Some(mining_address.clone());
        }
        
        if args.testnet {
            self.network.chain_id = TESTNET_CHAIN_ID;
        }
    }
}

/// Command line arguments that can override config
#[derive(Debug, Default)]
pub struct ConfigArgs {
    pub port: Option<u16>,
    pub data_dir: Option<String>,
    pub log_level: Option<String>,
    pub enable_mining: bool,
    pub mining_address: Option<String>,
    pub testnet: bool,
}

/// Configuration builder for programmatic setup
pub struct ConfigBuilder {
    config: PaliConfig,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        ConfigBuilder {
            config: PaliConfig::default(),
        }
    }
    
    pub fn network_port(mut self, port: u16) -> Self {
        self.config.network.port = port;
        self
    }
    
    pub fn data_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.config.blockchain.data_dir = path.into();
        self
    }
    
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.config.network.chain_id = chain_id;
        self
    }
    
    pub fn enable_mining(mut self, address: String) -> Self {
        self.config.mining.enabled = true;
        self.config.mining.reward_address = Some(address);
        self
    }
    
    pub fn mining_threads(mut self, threads: u32) -> Self {
        self.config.mining.threads = threads;
        self
    }
    
    pub fn log_level(mut self, level: String) -> Self {
        self.config.logging.level = level;
        self
    }
    
    pub fn testnet(mut self) -> Self {
        self.config.network.chain_id = TESTNET_CHAIN_ID;
        self
    }
    
    pub fn build(self) -> Result<PaliConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = PaliConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.network.port, DEFAULT_PORT);
        assert_eq!(config.network.chain_id, MAINNET_CHAIN_ID);
    }

    #[test]
    fn test_config_validation() {
        let mut config = PaliConfig::default();
        
        // Valid config should pass
        assert!(config.validate().is_ok());
        
        // Invalid port should fail
        config.network.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_save_load() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test-config.toml");
        
        let original_config = PaliConfig::default();
        original_config.save_to_file(&config_path).unwrap();
        
        let loaded_config = PaliConfig::load_from_file(&config_path).unwrap();
        assert_eq!(original_config.network.port, loaded_config.network.port);
    }

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .network_port(9999)
            .data_dir("/tmp/pali-test")
            .testnet()
            .build()
            .unwrap();
        
        assert_eq!(config.network.port, 9999);
        assert_eq!(config.network.chain_id, TESTNET_CHAIN_ID);
        assert!(config.is_testnet());
    }
}
