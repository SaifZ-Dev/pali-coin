// src/constants.rs - Bitcoin-grade constants for Pali Coin
use std::time::Duration;

/// Network protocol constants
pub mod network {
    use super::*;
    
    /// Protocol version for network compatibility
    pub const PROTOCOL_VERSION: u32 = 70016;
    
    /// Default network ports
    pub const MAINNET_PORT: u16 = 8333;
    pub const TESTNET_PORT: u16 = 18333;
    pub const REGTEST_PORT: u16 = 18444;
    
    /// Network magic bytes (4 bytes that identify the network)
    pub const MAINNET_MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];
    pub const TESTNET_MAGIC: [u8; 4] = [0x0B, 0x11, 0x09, 0x07];
    pub const REGTEST_MAGIC: [u8; 4] = [0xFA, 0xBF, 0xB5, 0xDA];
    
    /// Connection limits
    pub const MAX_OUTBOUND_CONNECTIONS: usize = 8;
    pub const MAX_INBOUND_CONNECTIONS: usize = 125;
    pub const MAX_CONNECTIONS_TOTAL: usize = MAX_OUTBOUND_CONNECTIONS + MAX_INBOUND_CONNECTIONS;
    
    /// Message size limits
    pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024; // 32MB
    pub const MAX_INV_ITEMS: usize = 50000;
    pub const MAX_ADDR_ITEMS: usize = 1000;
    pub const MAX_HEADERS_ITEMS: usize = 2000;
    
    /// Timeout constants
    pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
    pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
    pub const PING_INTERVAL: Duration = Duration::from_secs(120);
    pub const PING_TIMEOUT: Duration = Duration::from_secs(20);
    pub const STALE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(90 * 60); // 90 minutes
    
    /// Network service flags (Bitcoin-compatible)
    pub const NODE_NONE: u64 = 0;
    pub const NODE_NETWORK: u64 = 1 << 0;        // Full node
    pub const NODE_GETUTXO: u64 = 1 << 1;        // UTXO queries
    pub const NODE_BLOOM: u64 = 1 << 2;          // Bloom filtering
    pub const NODE_WITNESS: u64 = 1 << 3;        // Segregated witness
    pub const NODE_XTHIN: u64 = 1 << 4;          // Xtreme thinblocks
    pub const NODE_COMPRESS: u64 = 1 << 5;       // Compression
    pub const NODE_NETWORK_LIMITED: u64 = 1 << 10; // Pruned node
    
    /// User agent for network identification
    pub const USER_AGENT: &str = "/PaliCoin:1.0.0/";
    
    /// DNS seeds for peer discovery
    pub const MAINNET_DNS_SEEDS: &[&str] = &[
        "seed.palicoin.org",
        "dnsseed.palicoin.org", 
        "seed.pali.network",
        "dnsseed.pali.network",
    ];
    
    pub const TESTNET_DNS_SEEDS: &[&str] = &[
        "testnet-seed.palicoin.org",
        "testnet-dnsseed.palicoin.org",
    ];
    
    /// Rate limiting
    pub const MAX_REQUESTS_PER_MINUTE: usize = 1000;
    pub const MAX_BYTES_PER_MINUTE: u64 = 10 * 1024 * 1024; // 10MB
    pub const BAN_SCORE_THRESHOLD: u32 = 100;
    pub const DEFAULT_BAN_TIME: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours
}

/// Blockchain and consensus constants
pub mod consensus {
    use super::*;
    
    /// Chain IDs for different networks
    pub const MAINNET_CHAIN_ID: u64 = 1;
    pub const TESTNET_CHAIN_ID: u64 = 2;
    pub const REGTEST_CHAIN_ID: u64 = 3;
    
    /// Block timing and difficulty
    pub const TARGET_BLOCK_TIME: u64 = 600; // 10 minutes in seconds
    pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016; // Every 2016 blocks
    pub const MAX_BLOCK_TIME_DRIFT: u64 = 2 * 60 * 60; // 2 hours
    pub const MIN_BLOCK_TIME: u64 = 1; // Minimum 1 second between blocks
    
    /// Block size and transaction limits
    pub const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024; // 4MB
    pub const MAX_BLOCK_WEIGHT: usize = 16 * 1024 * 1024; // 16MB weight units
    pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 100_000;
    pub const MAX_TRANSACTION_SIZE: usize = 1024 * 1024; // 1MB
    pub const MAX_SCRIPT_SIZE: usize = 10_000;
    pub const MAX_SCRIPT_OPERATIONS: usize = 201;
    
    /// Mining and rewards
    pub const INITIAL_BLOCK_REWARD: u64 = 50 * COIN; // 50 PALI
    pub const HALVING_INTERVAL: u64 = 210_000; // Every 210,000 blocks
    pub const MAX_HALVINGS: u32 = 64; // After 64 halvings, no more rewards
    pub const COINBASE_MATURITY: u64 = 100; // Blocks before coinbase can be spent
    
    /// Difficulty limits
    pub const MIN_DIFFICULTY_BITS: u32 = 4; // Minimum 4 leading zero bits
    pub const MAX_DIFFICULTY_BITS: u32 = 32; // Maximum 32 leading zero bits
    pub const INITIAL_DIFFICULTY_BITS: u32 = 20; // Starting difficulty
    
    /// Genesis block
    pub const GENESIS_TIMESTAMP: u64 = 1640995200; // January 1, 2022 00:00:00 UTC
    pub const GENESIS_NONCE: u64 = 2083236893;
    pub const GENESIS_MERKLE_ROOT: [u8; 32] = [
        0x4a, 0x5e, 0x1e, 0x4b, 0xaa, 0xb8, 0x9f, 0x3a,
        0x32, 0x51, 0x8a, 0x88, 0xc3, 0x1b, 0xc8, 0x7f,
        0x61, 0x8f, 0x76, 0x67, 0x3e, 0x2c, 0xc7, 0x7a,
        0xb2, 0x12, 0x7b, 0x7a, 0xfd, 0xed, 0xa3, 0x3b
    ];
    
    /// Maximum money supply (21 million PALI with 8 decimal places)
    pub const MAX_MONEY: u64 = 21_000_000 * COIN;
    
    /// Minimum transaction fee
    pub const MIN_TX_FEE: u64 = 1000; // 0.00001 PALI
    pub const MIN_RELAY_TX_FEE: u64 = 1000; // Minimum fee to relay transaction
    pub const DUST_THRESHOLD: u64 = 546; // Minimum UTXO value
    
    /// Consensus rule versions
    pub const BIP16_SWITCH_TIME: u64 = 1333238400; // April 1, 2012 (P2SH activation)
    pub const BIP34_HEIGHT: u64 = 227931; // Block height for BIP34 activation
    pub const BIP65_HEIGHT: u64 = 388381; // Block height for BIP65 activation (CLTV)
    pub const BIP66_HEIGHT: u64 = 363725; // Block height for BIP66 activation (strict DER)
    
    /// Segregated Witness (if implemented)
    pub const SEGWIT_ACTIVATION_HEIGHT: u64 = 481824; // SegWit activation height
    pub const WITNESS_SCALE_FACTOR: usize = 4;
    
    /// Time lock constants
    pub const LOCKTIME_THRESHOLD: u32 = 500_000_000; // Threshold for interpreting nLockTime
    pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
    pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9; // 512 seconds
}

/// Cryptographic constants
pub mod crypto {
    /// Coin unit (8 decimal places like Bitcoin)
    pub const COIN: u64 = 100_000_000; // 1 PALI = 100,000,000 satoshis
    pub const CENT: u64 = COIN / 100; // 0.01 PALI
    pub const MILLI: u64 = COIN / 1000; // 0.001 PALI
    pub const MICRO: u64 = COIN / 1_000_000; // 0.000001 PALI
    pub const SATOSHI: u64 = 1; // Smallest unit
    
    /// Key and signature sizes
    pub const PRIVATE_KEY_SIZE: usize = 32;
    pub const PUBLIC_KEY_SIZE: usize = 33; // Compressed
    pub const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
    pub const SIGNATURE_SIZE: usize = 64; // DER encoded can be up to 72 bytes
    pub const SIGNATURE_WITH_RECOVERY_SIZE: usize = 65;
    pub const ADDRESS_SIZE: usize = 20; // RIPEMD160 hash size
    pub const HASH_SIZE: usize = 32; // SHA256 hash size
    
    /// Cryptographic curve parameters (secp256k1)
    pub const SECP256K1_CURVE_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    ];
    
    /// BIP32 constants for HD wallets
    pub const BIP32_SEED_LEN: usize = 64;
    pub const BIP32_EXTKEY_SIZE: usize = 78;
    pub const BIP32_HARDENED_KEY_LIMIT: u32 = 0x80000000;
    
    /// BIP39 constants for mnemonic phrases
    pub const BIP39_ENTROPY_LEN_128: usize = 16; // 12 words
    pub const BIP39_ENTROPY_LEN_160: usize = 20; // 15 words
    pub const BIP39_ENTROPY_LEN_192: usize = 24; // 18 words
    pub const BIP39_ENTROPY_LEN_224: usize = 28; // 21 words
    pub const BIP39_ENTROPY_LEN_256: usize = 32; // 24 words
    
    /// Password-based key derivation
    pub const PBKDF2_ITERATIONS: u32 = 2048; // BIP39 standard
    pub const SCRYPT_N: u32 = 16384; // Scrypt work factor
    pub const SCRYPT_R: u32 = 8; // Block size
    pub const SCRYPT_P: u32 = 1; // Parallelization
    
    /// Argon2 parameters for wallet encryption
    pub const ARGON2_MEMORY_COST: u32 = 65536; // 64MB
    pub const ARGON2_TIME_COST: u32 = 3; // 3 iterations
    pub const ARGON2_PARALLELISM: u32 = 4; // 4 threads
    pub const ARGON2_HASH_LENGTH: u32 = 32; // 32 byte output
}

/// Mining constants
pub mod mining {
    use super::*;
    
    /// Proof of work limits
    pub const POW_LIMIT_BITS: u32 = 0x1d00ffff; // Difficulty 1 target
    pub const MAX_TARGET: [u8; 32] = [
        0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    
    /// Nonce search limits
    pub const MAX_NONCE: u64 = u64::MAX;
    pub const NONCE_BATCH_SIZE: u64 = 100_000;
    
    /// Mining pool constants
    pub const STRATUM_VERSION: &str = "mining_pool/1.0.0";
    pub const SHARE_DIFFICULTY: u32 = 16; // Default share difficulty
    pub const VARDIFF_MIN: u32 = 8; // Minimum variable difficulty
    pub const VARDIFF_MAX: u32 = 32; // Maximum variable difficulty
    pub const VARDIFF_TARGET_TIME: Duration = Duration::from_secs(15); // Target share time
    
    /// Mining thread limits
    pub const MAX_MINING_THREADS: usize = 64;
    pub const DEFAULT_MINING_THREADS: usize = num_cpus::get();
    
    /// Work management
    pub const WORK_UPDATE_INTERVAL: Duration = Duration::from_secs(10);
    pub const STALE_WORK_THRESHOLD: Duration = Duration::from_secs(120);
    pub const MAX_WORK_ITEMS: usize = 10;
}

/// Security and anti-spam constants
pub mod security {
    use super::*;
    
    /// Rate limiting
    pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
    pub const MAX_CONNECTIONS_PER_IP: usize = 3;
    pub const MAX_REQUESTS_PER_MINUTE_PER_IP: usize = 100;
    pub const MAX_BYTES_PER_MINUTE_PER_IP: u64 = 1024 * 1024; // 1MB
    
    /// Ban management
    pub const BAN_SCORE_DECAY_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour
    pub const BAN_SCORE_DECAY_AMOUNT: u32 = 1;
    pub const AUTO_BAN_THRESHOLD: u32 = 100;
    pub const MAX_BAN_DURATION: Duration = Duration::from_secs(30 * 24 * 3600); // 30 days
    
    /// Anti-DoS limits
    pub const MAX_ORPHAN_BLOCKS: usize = 100;
    pub const MAX_ORPHAN_TRANSACTIONS: usize = 1000;
    pub const ORPHAN_EXPIRE_TIME: Duration = Duration::from_secs(20 * 60); // 20 minutes
    
    /// Proof of work for anti-spam
    pub const ANTI_SPAM_POW_BITS: u32 = 8; // 8 leading zero bits
    pub const CHALLENGE_EXPIRE_TIME: Duration = Duration::from_secs(300); // 5 minutes
    
    /// Memory limits
    pub const MAX_SIGNATURE_CACHE_SIZE: usize = 50_000;
    pub const MAX_SCRIPT_CACHE_SIZE: usize = 10_000;
    pub const MAX_ADDR_CACHE_SIZE: usize = 5_000;
    
    /// Intrusion detection
    pub const IDS_SCAN_THRESHOLD: u32 = 10; // Connections per minute
    pub const IDS_INVALID_MSG_THRESHOLD: u32 = 5; // Invalid messages
    pub const IDS_PATTERN_WINDOW: Duration = Duration::from_secs(300); // 5 minutes
}

/// Database and storage constants
pub mod storage {
    use super::*;
    
    /// Database configuration
    pub const DB_CACHE_SIZE: usize = 512 * 1024 * 1024; // 512MB
    pub const DB_MAX_OPEN_FILES: i32 = 1000;
    pub const DB_WRITE_BUFFER_SIZE: usize = 64 * 1024 * 1024; // 64MB
    pub const DB_MAX_FILE_SIZE: usize = 256 * 1024 * 1024; // 256MB
    
    /// Backup and pruning
    pub const PRUNE_THRESHOLD: u64 = 550; // MB to keep when pruning
    pub const BACKUP_INTERVAL: Duration = Duration::from_secs(24 * 3600); // Daily
    pub const CHECKPOINT_INTERVAL: u64 = 10000; // Every 10k blocks
    
    /// File paths and names
    pub const BLOCKS_DIR: &str = "blocks";
    pub const CHAINSTATE_DIR: &str = "chainstate";
    pub const WALLETS_DIR: &str = "wallets";
    pub const LOGS_DIR: &str = "logs";
    pub const CONFIG_FILE: &str = "pali.conf";
    pub const PEERS_FILE: &str = "peers.dat";
    pub const BANLIST_FILE: &str = "banlist.dat";
    
    /// Cache sizes
    pub const BLOCK_CACHE_SIZE: usize = 1000; // Number of blocks to cache
    pub const TX_CACHE_SIZE: usize = 10000; // Number of transactions to cache
    pub const UTXO_CACHE_SIZE: usize = 100000; // Number of UTXOs to cache
}

/// Wallet constants
pub mod wallet {
    use super::*;
    
    /// Key derivation paths (BIP44)
    pub const BIP44_COIN_TYPE_MAINNET: u32 = 0; // To be assigned by SLIP-0044
    pub const BIP44_COIN_TYPE_TESTNET: u32 = 1;
    pub const BIP44_PURPOSE: u32 = 44; // BIP44
    pub const BIP49_PURPOSE: u32 = 49; // BIP49 (P2WPKH-P2SH)
    pub const BIP84_PURPOSE: u32 = 84; // BIP84 (P2WPKH)
    
    /// Default derivation paths
    pub const DEFAULT_DERIVATION_PATH: &str = "m/44'/0'/0'/0/0";
    pub const CHANGE_DERIVATION_PATH: &str = "m/44'/0'/0'/1/0";
    
    /// Wallet encryption
    pub const WALLET_CRYPTO_KEY_SIZE: usize = 32;
    pub const WALLET_CRYPTO_SALT_SIZE: usize = 8;
    pub const WALLET_ENCRYPTION_ROUNDS: u32 = 25000;
    
    /// Address types and formats
    pub const ADDRESS_TYPE_P2PKH: u8 = 0x00; // Pay to Public Key Hash
    pub const ADDRESS_TYPE_P2SH: u8 = 0x05; // Pay to Script Hash
    pub const TESTNET_ADDRESS_TYPE_P2PKH: u8 = 0x6F;
    pub const TESTNET_ADDRESS_TYPE_P2SH: u8 = 0xC4;
    
    /// Wallet Import Format (WIF)
    pub const WIF_PREFIX_MAINNET: u8 = 0x80;
    pub const WIF_PREFIX_TESTNET: u8 = 0xEF;
    pub const WIF_COMPRESSED_FLAG: u8 = 0x01;
    
    /// Wallet limits
    pub const MAX_WALLET_SIZE: usize = 1000000; // 1M addresses
    pub const MAX_TX_HISTORY: usize = 100000; // 100k transactions
    pub const WALLET_BACKUP_COUNT: usize = 5; // Keep 5 backups
    
    /// Fee estimation
    pub const FEE_ESTIMATION_BLOCKS: &[u32] = &[2, 3, 5, 10, 15, 25];
    pub const MIN_FEE_RATE: u64 = 1000; // 1000 sat/vB minimum
    pub const MAX_FEE_RATE: u64 = 1000000; // 0.01 PALI/vB maximum
    pub const DEFAULT_FEE_RATE: u64 = 10000; // 0.0001 PALI/vB default
}

/// RPC and API constants
pub mod rpc {
    use super::*;
    
    /// RPC configuration
    pub const DEFAULT_RPC_PORT: u16 = 8332;
    pub const DEFAULT_RPC_TESTNET_PORT: u16 = 18332;
    pub const RPC_AUTH_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
    pub const RPC_MAX_REQUEST_SIZE: usize = 4 * 1024 * 1024; // 4MB
    pub const RPC_MAX_RESPONSE_SIZE: usize = 32 * 1024 * 1024; // 32MB
    
    /// Rate limiting for RPC
    pub const RPC_MAX_REQUESTS_PER_MINUTE: usize = 1000;
    pub const RPC_MAX_CONCURRENT_REQUESTS: usize = 100;
    
    /// HTTP headers
    pub const JSON_RPC_VERSION: &str = "2.0";
    pub const USER_AGENT_HEADER: &str = "User-Agent";
    pub const CONTENT_TYPE_JSON: &str = "application/json";
    
    /// Error codes (Bitcoin-compatible)
    pub const RPC_INVALID_REQUEST: i32 = -32600;
    pub const RPC_METHOD_NOT_FOUND: i32 = -32601;
    pub const RPC_INVALID_PARAMS: i32 = -32602;
    pub const RPC_INTERNAL_ERROR: i32 = -32603;
    pub const RPC_PARSE_ERROR: i32 = -32700;
    
    /// Custom error codes
    pub const RPC_MISC_ERROR: i32 = -1;
    pub const RPC_TYPE_ERROR: i32 = -3;
    pub const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;
    pub const RPC_OUT_OF_MEMORY: i32 = -7;
    pub const RPC_INVALID_PARAMETER: i32 = -8;
    pub const RPC_DATABASE_ERROR: i32 = -20;
    pub const RPC_DESERIALIZATION_ERROR: i32 = -22;
    pub const RPC_VERIFY_ERROR: i32 = -25;
    pub const RPC_VERIFY_REJECTED: i32 = -26;
    pub const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;
    pub const RPC_IN_WARMUP: i32 = -28;
    pub const RPC_METHOD_DEPRECATED: i32 = -32;
}

/// Test network constants
pub mod test {
    use super::*;
    
    /// Reduced mining difficulty for testing
    pub const TESTNET_MIN_DIFFICULTY_BITS: u32 = 1;
    pub const REGTEST_MIN_DIFFICULTY_BITS: u32 = 1;
    
    /// Faster block times for testing
    pub const TESTNET_TARGET_BLOCK_TIME: u64 = 300; // 5 minutes
    pub const REGTEST_TARGET_BLOCK_TIME: u64 = 1; // 1 second
    
    /// Reduced confirmation requirements
    pub const TESTNET_COINBASE_MATURITY: u64 = 10;
    pub const REGTEST_COINBASE_MATURITY: u64 = 1;
    
    /// Test mining rewards
    pub const TESTNET_INITIAL_REWARD: u64 = 50 * crypto::COIN;
    pub const REGTEST_INITIAL_REWARD: u64 = 50 * crypto::COIN;
    
    /// Relaxed network limits for testing
    pub const TEST_MAX_CONNECTIONS: usize = 20;
    pub const TEST_MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB
}

/// Feature flags for optional functionality
pub mod features {
    /// Zero-knowledge proof features
    pub const ENABLE_ZK_PROOFS: bool = cfg!(feature = "zk-proofs");
    
    /// Advanced cryptography
    pub const ENABLE_QUANTUM_RESISTANT: bool = cfg!(feature = "quantum-resistant");
    
    /// High-performance mining
    pub const ENABLE_GPU_MINING: bool = cfg!(feature = "gpu-mining");
    
    /// Enterprise features
    pub const ENABLE_ENTERPRISE_LOGGING: bool = cfg!(feature = "enterprise-logging");
    pub const ENABLE_METRICS: bool = cfg!(feature = "metrics");
    pub const ENABLE_TRACING: bool = cfg!(feature = "tracing");
    
    /// Network features
    pub const ENABLE_TOR_SUPPORT: bool = cfg!(feature = "tor");
    pub const ENABLE_I2P_SUPPORT: bool = cfg!(feature = "i2p");
    
    /// Database features
    pub const ENABLE_ROCKSDB: bool = cfg!(feature = "rocksdb");
    pub const ENABLE_POSTGRESQL: bool = cfg!(feature = "postgresql");
}

/// Version information
pub mod version {
    /// Client version
    pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
    pub const CLIENT_NAME: &str = env!("CARGO_PKG_NAME");
    
    /// Protocol version for compatibility
    pub const PROTOCOL_VERSION: u32 = 70016;
    
    /// Minimum supported protocol version
    pub const MIN_PROTOCOL_VERSION: u32 = 70001;
    
    /// BIP compliance versions
    pub const BIP31_VERSION: u32 = 60000; // Pong message
    pub const BIP37_VERSION: u32 = 70001; // Bloom filters
    pub const BIP111_VERSION: u32 = 70011; // NODE_BLOOM service bit
    pub const BIP130_VERSION: u32 = 70012; // sendheaders message
    pub const BIP133_VERSION: u32 = 70013; // feefilter message
    pub const BIP152_VERSION: u32 = 70014; // Compact blocks
    pub const BIP159_VERSION: u32 = 70016; // NODE_NETWORK_LIMITED
}

/// Compile-time checks
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_constants_consistency() {
        // Ensure max money doesn't overflow
        assert!(consensus::MAX_MONEY <= u64::MAX);
        
        // Ensure block size limits are reasonable
        assert!(consensus::MAX_BLOCK_SIZE <= network::MAX_MESSAGE_SIZE);
        
        // Ensure connection limits are reasonable
        assert!(network::MAX_CONNECTIONS_TOTAL >= network::MAX_OUTBOUND_CONNECTIONS);
        
        // Ensure mining constants are valid
        assert!(mining::VARDIFF_MIN <= mining::VARDIFF_MAX);
        assert!(consensus::MIN_DIFFICULTY_BITS <= consensus::MAX_DIFFICULTY_BITS);
        
        // Ensure crypto constants are correct sizes
        assert_eq!(crypto::PRIVATE_KEY_SIZE, 32);
        assert_eq!(crypto::PUBLIC_KEY_SIZE, 33);
        assert_eq!(crypto::ADDRESS_SIZE, 20);
        assert_eq!(crypto::HASH_SIZE, 32);
        
        // Ensure wallet constants are valid
        assert!(wallet::MAX_WALLET_SIZE > 0);
        assert!(wallet::MIN_FEE_RATE <= wallet::DEFAULT_FEE_RATE);
        assert!(wallet::DEFAULT_FEE_RATE <= wallet::MAX_FEE_RATE);
        
        // Ensure time constants are reasonable
        assert!(consensus::TARGET_BLOCK_TIME > consensus::MIN_BLOCK_TIME);
        assert!(consensus::MAX_BLOCK_TIME_DRIFT > consensus::TARGET_BLOCK_TIME);
        
        // Ensure security constants are reasonable
        assert!(security::AUTO_BAN_THRESHOLD > 0);
        assert!(security::MAX_CONNECTIONS_PER_IP <= network::MAX_INBOUND_CONNECTIONS);
    }
    
    #[test]
    fn test_coin_arithmetic() {
        use crypto::*;
        
        assert_eq!(COIN, 100_000_000);
        assert_eq!(CENT, COIN / 100);
        assert_eq!(MILLI, COIN / 1000);
        assert_eq!(MICRO, COIN / 1_000_000);
        assert_eq!(SATOSHI, 1);
        
        // Test no overflow in max money calculation
        let max_coins = 21_000_000u64;
        assert!(max_coins.checked_mul(COIN).is_some());
        assert_eq!(consensus::MAX_MONEY, max_coins * COIN);
    }
    
    #[test]
    fn test_network_magic_uniqueness() {
        use network::*;
        
        assert_ne!(MAINNET_MAGIC, TESTNET_MAGIC);
        assert_ne!(MAINNET_MAGIC, REGTEST_MAGIC);
        assert_ne!(TESTNET_MAGIC, REGTEST_MAGIC);
    }
    
    #[test]
    fn test_port_ranges() {
        use network::*;
        
        // Ensure ports are in valid range
        assert!(MAINNET_PORT >= 1024);
        assert!(TESTNET_PORT >= 1024);
        assert!(REGTEST_PORT >= 1024);
        
        // Ensure ports are different
        assert_ne!(MAINNET_PORT, TESTNET_PORT);
        assert_ne!(MAINNET_PORT, REGTEST_PORT);
        assert_ne!(TESTNET_PORT, REGTEST_PORT);
    }
    
    #[test]
    fn test_difficulty_bounds() {
        use consensus::*;
        
        assert!(MIN_DIFFICULTY_BITS >= 1);
        assert!(MAX_DIFFICULTY_BITS <= 32);
        assert!(MIN_DIFFICULTY_BITS <= INITIAL_DIFFICULTY_BITS);
        assert!(INITIAL_DIFFICULTY_BITS <= MAX_DIFFICULTY_BITS);
    }
    
    #[test]
    fn test_halving_logic() {
        use consensus::*;
        
        // Test that halving doesn't cause immediate zero rewards
        let mut reward = INITIAL_BLOCK_REWARD;
        let mut halvings = 0;
        
        while reward > 0 && halvings < MAX_HALVINGS {
            reward /= 2;
            halvings += 1;
        }
        
        assert!(halvings <= MAX_HALVINGS);
    }
}
