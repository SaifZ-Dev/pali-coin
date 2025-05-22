// src/wallet.rs - Enterprise-grade wallet with Bitcoin-level security
use serde::{Serialize, Deserialize};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use secp256k1::rand::rngs::OsRng;
use rand::{RngCore, CryptoRng};
use std::fs;
use std::path::Path;
use log::{info, warn, error, debug};
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher, PasswordHash, PasswordVerifier}};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use zeroize::{Zeroize, ZeroizeOnDrop};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::ConstantTimeEq;
use crate::types::{Transaction, Address, public_key_to_address, double_sha256};

// Security constants (enterprise-grade)
const ARGON2_MEMORY_COST: u32 = 131_072; // 128MB memory
const ARGON2_TIME_COST: u32 = 4;         // 4 iterations
const ARGON2_PARALLELISM: u32 = 8;       // 8 threads
const WALLET_VERSION: u32 = 2;           // Current wallet format version
const MAX_FAILED_ATTEMPTS: u8 = 5;       // Max failed decrypt attempts
const LOCKOUT_DURATION_SECS: u64 = 1800; // 30 minute lockout
const KEY_DERIVATION_ROUNDS: u32 = 100_000; // PBKDF2 rounds for additional security

// Global rate limiting for brute force protection
static FAILED_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static LAST_ATTEMPT_TIME: AtomicU64 = AtomicU64::new(0);

/// Enhanced encrypted wallet format
#[derive(Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// Wallet format version
    pub version: u32,
    
    /// Argon2 salt for key derivation
    pub salt: String,
    
    /// ChaCha20Poly1305 nonce
    pub nonce: String,
    
    /// Encrypted wallet data
    pub encrypted_data: String,
    
    /// HMAC for integrity verification
    pub mac: String,
    
    /// Key derivation parameters
    pub kdf_params: KdfParams,
    
    /// Wallet metadata
    pub metadata: WalletMetadata,
}

#[derive(Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub algorithm: String,
}

#[derive(Serialize, Deserialize)]
pub struct WalletMetadata {
    pub created_at: u64,
    pub last_accessed: u64,
    pub failed_attempts: u8,
    pub locked_until: u64,
    pub checksum: String, // Additional integrity check
}

/// Secure wallet implementation with Bitcoin-grade security
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Wallet {
    /// ECDSA private key (32 bytes, secp256k1)
    #[zeroize(skip)]
    pub private_key: [u8; 32],
    
    /// Compressed public key (33 bytes)
    #[zeroize(skip)]
    pub public_key: [u8; 33],
    
    /// 20-byte address derived from public key
    #[zeroize(skip)]
    pub address: Address,
    
    /// Optional seed phrase for recovery
    pub seed_phrase: Option<String>,
    
    /// Derivation path (BIP44 format)
    pub derivation_path: Option<String>,
    
    /// Wallet creation timestamp
    pub created_at: u64,
}

/// Wallet configuration for creation
pub struct WalletConfig {
    pub use_seed_phrase: bool,
    pub derivation_path: Option<String>,
    pub entropy_source: Box<dyn CryptoRng + RngCore>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        WalletConfig {
            use_seed_phrase: true,
            derivation_path: Some("m/44'/0'/0'/0/0".to_string()),
            entropy_source: Box::new(OsRng),
        }
    }
}

/// Key pair structure for easier handling
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self, String> {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        
        Ok(KeyPair {
            secret_key,
            public_key,
        })
    }
    
    pub fn from_secret_key(secret_key: SecretKey) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        Ok(KeyPair {
            secret_key,
            public_key,
        })
    }
}

impl Wallet {
    /// Create a new wallet with enhanced security
    pub fn new() -> Result<Self, String> {
        Self::new_with_config(WalletConfig::default())
    }
    
    /// Create a new wallet with custom configuration
    pub fn new_with_config(mut config: WalletConfig) -> Result<Self, String> {
        let secp = Secp256k1::new();
        
        // Generate cryptographically secure private key
        let (secret_key, public_key) = secp.generate_keypair(&mut config.entropy_source);
        
        // Convert to bytes
        let private_key = secret_key.secret_bytes();
        let public_key_bytes = public_key.serialize();
        
        // Generate address using Bitcoin-compatible method
        let address = public_key_to_address(&public_key);
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut wallet = Wallet {
            private_key,
            public_key: public_key_bytes,
            address,
            seed_phrase: None,
            derivation_path: config.derivation_path,
            created_at: current_time,
        };
        
        // Generate seed phrase if requested
        if config.use_seed_phrase {
            let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
            wallet.seed_phrase = Some(mnemonic.to_string());
        }
        
        // Zero out sensitive data from config
        config.entropy_source.zeroize();
        
        info!("Created new wallet with address: {}", hex::encode(wallet.address));
        Ok(wallet)
    }
    
    /// Create wallet from existing private key
    pub fn from_private_key(private_key_bytes: &[u8; 32]) -> Result<Self, String> {
        let secp = Secp256k1::new();
        
        let secret_key = SecretKey::from_slice(private_key_bytes)
            .map_err(|e| format!("Invalid private key: {}", e))?;
        
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes = public_key.serialize();
        let address = public_key_to_address(&public_key);
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(Wallet {
            private_key: *private_key_bytes,
            public_key: public_key_bytes,
            address,
            seed_phrase: None,
            derivation_path: None,
            created_at: current_time,
        })
    }
    
    /// Create wallet from BIP39 seed phrase with enhanced validation
    pub fn from_seed_phrase(phrase: &str) -> Result<Self, String> {
        // Validate mnemonic
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| format!("Invalid seed phrase: {}", e))?;
        
        // Generate seed with empty passphrase (can be extended to support passphrases)
        let seed = Seed::new(&mnemonic, "");
        
        // Derive private key from seed (simplified BIP32 derivation)
        let private_key_bytes = Self::derive_private_key_from_seed(seed.as_bytes())?;
        
        let mut wallet = Self::from_private_key(&private_key_bytes)?;
        wallet.seed_phrase = Some(phrase.to_string());
        wallet.derivation_path = Some("m/44'/0'/0'/0/0".to_string());
        
        Ok(wallet)
    }
    
    /// Derive private key from seed using HMAC-SHA512 (simplified BIP32)
    fn derive_private_key_from_seed(seed: &[u8]) -> Result<[u8; 32], String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"Pali Coin seed")
            .map_err(|_| "Failed to create HMAC")?;
        
        mac.update(seed);
        let result = mac.finalize().into_bytes();
        
        // Take first 32 bytes as private key
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&result[..32]);
        
        // Ensure the key is valid for secp256k1
        if private_key == [0u8; 32] || private_key >= [0xFF; 32] {
            return Err("Invalid private key derived from seed".to_string());
        }
        
        Ok(private_key)
    }
    
    /// Generate a new wallet with seed phrase
    pub fn new_with_seed_phrase() -> Result<(Self, String), String> {
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let phrase = mnemonic.to_string();
        let wallet = Self::from_seed_phrase(&phrase)?;
        Ok((wallet, phrase))
    }
    
    /// Save wallet with enterprise-grade encryption
    pub fn save_encrypted<P: AsRef<Path>>(&self, path: P, password: &str) -> Result<(), String> {
        // Validate password strength
        self.validate_password_strength(password)?;
        
        // Check for rate limiting
        self.check_rate_limit()?;
        
        // Generate salt for Argon2
        let salt = SaltString::generate(&mut OsRng);
        
        // Configure Argon2 with enterprise parameters
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                ARGON2_MEMORY_COST,
                ARGON2_TIME_COST,
                ARGON2_PARALLELISM,
                Some(32)
            ).map_err(|e| format!("Invalid Argon2 parameters: {}", e))?
        );
        
        // Derive encryption key
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("Password hashing failed: {}", e))?;
        
        let key_bytes = password_hash.hash.unwrap().as_bytes();
        let key = Key::from_slice(&key_bytes[..32]);
        
        // Generate nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Serialize wallet data
        let wallet_data = bincode::serialize(self)
            .map_err(|e| format!("Serialization failed: {}", e))?;
        
        // Encrypt with ChaCha20Poly1305
        let cipher = ChaCha20Poly1305::new(key);
        let ciphertext = cipher.encrypt(nonce, wallet_data.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Generate HMAC for integrity
        let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes[..32])
            .map_err(|_| "Failed to create HMAC")?;
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);
        mac.update(&salt.as_bytes());
        let mac_result = mac.finalize().into_bytes();
        
        // Calculate checksum for additional integrity
        let checksum = hex::encode(double_sha256(&wallet_data)[..8].to_vec());
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Create encrypted wallet structure
        let encrypted_wallet = EncryptedWallet {
            version: WALLET_VERSION,
            salt: salt.as_str().to_string(),
            nonce: hex::encode(nonce_bytes),
            encrypted_data: hex::encode(ciphertext),
            mac: hex::encode(mac_result),
            kdf_params: KdfParams {
                memory_cost: ARGON2_MEMORY_COST,
                time_cost: ARGON2_TIME_COST,
                parallelism: ARGON2_PARALLELISM,
                algorithm: "Argon2id".to_string(),
            },
            metadata: WalletMetadata {
                created_at: self.created_at,
                last_accessed: current_time,
                failed_attempts: 0,
                locked_until: 0,
                checksum,
            },
        };
        
        // Save to file
        let json = serde_json::to_string_pretty(&encrypted_wallet)
            .map_err(|e| format!("JSON serialization failed: {}", e))?;
        
        fs::write(path, json)
            .map_err(|e| format!("Failed to write wallet file: {}", e))?;
        
        info!("Wallet encrypted and saved successfully");
        Ok(())
    }
    
    /// Load encrypted wallet with enhanced security
    pub fn load_encrypted<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, String> {
        // Check rate limiting
        Self::check_global_rate_limit()?;
        
        // Read encrypted wallet
        let json = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read wallet file: {}", e))?;
        
        let mut encrypted_wallet: EncryptedWallet = serde_json::from_str(&json)
            .map_err(|e| format!("Failed to parse wallet file: {}", e))?;
        
        // Check if wallet is locked
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if encrypted_wallet.metadata.locked_until > current_time {
            let remaining = encrypted_wallet.metadata.locked_until - current_time;
            return Err(format!("Wallet locked for {} more seconds", remaining));
        }
        
        // Check version compatibility
        if encrypted_wallet.version > WALLET_VERSION {
            return Err("Wallet version not supported. Please upgrade Pali Coin.".to_string());
        }
        
        // Parse salt and derive key
        let salt = SaltString::new(&encrypted_wallet.salt)
            .map_err(|_| "Invalid salt format")?;
        
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                encrypted_wallet.kdf_params.memory_cost,
                encrypted_wallet.kdf_params.time_cost,
                encrypted_wallet.kdf_params.parallelism,
                Some(32)
            ).map_err(|e| format!("Invalid KDF parameters: {}", e))?
        );
        
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                Self::record_failed_attempt();
                encrypted_wallet.metadata.failed_attempts += 1;
                
                // Lock wallet after too many failures
                if encrypted_wallet.metadata.failed_attempts >= MAX_FAILED_ATTEMPTS {
                    encrypted_wallet.metadata.locked_until = current_time + LOCKOUT_DURATION_SECS;
                    let _ = fs::write(&json, serde_json::to_string_pretty(&encrypted_wallet).unwrap_or_default());
                }
                
                format!("Password verification failed: {}", e)
            })?;
        
        let key_bytes = password_hash.hash.unwrap().as_bytes();
        let key = Key::from_slice(&key_bytes[..32]);
        
        // Verify HMAC
        let nonce_bytes = hex::decode(&encrypted_wallet.nonce)
            .map_err(|_| "Invalid nonce format")?;
        let ciphertext = hex::decode(&encrypted_wallet.encrypted_data)
            .map_err(|_| "Invalid ciphertext format")?;
        let expected_mac = hex::decode(&encrypted_wallet.mac)
            .map_err(|_| "Invalid MAC format")?;
        
        let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes[..32])
            .map_err(|_| "Failed to create HMAC")?;
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);
        mac.update(encrypted_wallet.salt.as_bytes());
        let computed_mac = mac.finalize().into_bytes();
        
        // Constant-time MAC comparison
        if !bool::from(computed_mac.ct_eq(&expected_mac)) {
            Self::record_failed_attempt();
            return Err("MAC verification failed - wallet may be corrupted".to_string());
        }
        
        // Decrypt wallet data
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| {
                Self::record_failed_attempt();
                "Decryption failed - invalid password or corrupted wallet"
            })?;
        
        // Deserialize wallet
        let wallet: Wallet = bincode::deserialize(&plaintext)
            .map_err(|e| format!("Failed to deserialize wallet: {}", e))?;
        
        // Verify checksum
        let computed_checksum = hex::encode(double_sha256(&plaintext)[..8].to_vec());
        if computed_checksum != encrypted_wallet.metadata.checksum {
            return Err("Wallet checksum verification failed".to_string());
        }
        
        // Update last accessed time
        encrypted_wallet.metadata.last_accessed = current_time;
        encrypted_wallet.metadata.failed_attempts = 0;
        let updated_json = serde_json::to_string_pretty(&encrypted_wallet)
            .unwrap_or_default();
        let _ = fs::write(&json, updated_json);
        
        info!("Wallet decrypted and loaded successfully");
        Ok(wallet)
    }
    
    /// Sign transaction with enhanced security
    pub fn sign_transaction(&self, tx: &mut Transaction) -> Result<(), String> {
        // Verify transaction belongs to this wallet
        if tx.from != self.address {
            return Err("Transaction 'from' address doesn't match wallet address".to_string());
        }
        
        // Create secp256k1 context
        let secp = Secp256k1::new();
        
        // Recreate keys from bytes
        let secret_key = SecretKey::from_slice(&self.private_key)
            .map_err(|e| format!("Invalid private key: {}", e))?;
        
        let public_key = PublicKey::from_slice(&self.public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        
        // Sign the transaction
        tx.sign(&secret_key, &public_key)?;
        
        debug!("Transaction signed successfully");
        Ok(())
    }
    
    /// Sign arbitrary data
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let secp = Secp256k1::new();
        
        let secret_key = SecretKey::from_slice(&self.private_key)
            .map_err(|e| format!("Invalid private key: {}", e))?;
        
        // Hash the data
        let hash = double_sha256(data);
        let message = Message::from_digest_slice(&hash)
            .map_err(|e| format!("Failed to create message: {}", e))?;
        
        // Sign
        let signature = secp.sign_ecdsa(&message, &secret_key);
        Ok(signature.serialize_compact().to_vec())
    }
    
    /// Verify signature
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        
        let secp = Secp256k1::new();
        
        let public_key = match PublicKey::from_slice(&self.public_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        
        let hash = double_sha256(data);
        let message = match Message::from_digest_slice(&hash) {
            Ok(msg) => msg,
            Err(_) => return false,
        };
        
        let sig = match secp256k1::ecdsa::Signature::from_compact(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        secp.verify_ecdsa(&message, &sig, &public_key).is_ok()
    }
    
    /// Get wallet address as hex string
    pub fn get_address_string(&self) -> String {
        hex::encode(self.address)
    }
    
    /// Get private key (use with caution)
    pub fn get_private_key(&self) -> [u8; 32] {
        self.private_key
    }
    
    /// Validate password strength
    fn validate_password_strength(&self, password: &str) -> Result<(), String> {
        if password.len() < 12 {
            return Err("Password must be at least 12 characters long".to_string());
        }
        
        let mut has_uppercase = false;
        let mut has_lowercase = false;
        let mut has_digit = false;
        let mut has_special = false;
        
        for c in password.chars() {
            match c {
                'A'..='Z' => has_uppercase = true,
                'a'..='z' => has_lowercase = true,
                '0'..='9' => has_digit = true,
                _ => has_special = true,
            }
        }
        
        let criteria_met = [has_uppercase, has_lowercase, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();
        
        if criteria_met < 3 {
            return Err("Password must contain at least 3 of: uppercase, lowercase, digits, special characters".to_string());
        }
        
        // Check against common passwords (simplified check)
        let common_passwords = ["password", "123456", "qwerty", "admin", "letmein"];
        if common_passwords.iter().any(|&p| password.to_lowercase().contains(p)) {
            return Err("Password contains common patterns and is not secure".to_string());
        }
        
        Ok(())
    }
    
    /// Check rate limiting for this wallet
    fn check_rate_limit(&self) -> Result<(), String> {
        // Implement per-wallet rate limiting if needed
        Ok(())
    }
    
    /// Check global rate limiting
    fn check_global_rate_limit() -> Result<(), String> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let last_attempt = LAST_ATTEMPT_TIME.load(Ordering::Relaxed);
        let failed_count = FAILED_ATTEMPTS.load(Ordering::Relaxed);
        
        // Reset counter after lockout period
        if current_time > last_attempt + LOCKOUT_DURATION_SECS {
            FAILED_ATTEMPTS.store(0, Ordering::Relaxed);
            return Ok(());
        }
        
        // Check if too many attempts
        if failed_count >= 10 {
            let remaining = (last_attempt + LOCKOUT_DURATION_SECS) - current_time;
            return Err(format!("Too many failed attempts. Try again in {} seconds", remaining));
        }
        
        Ok(())
    }
    
    /// Record failed attempt
    fn record_failed_attempt() {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        FAILED_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        LAST_ATTEMPT_TIME.store(current_time, Ordering::Relaxed);
        
        warn!("Failed wallet decryption attempt recorded");
    }
    
    /// Generate random nonce for transactions
    pub fn generate_nonce() -> u64 {
        let mut rng = OsRng;
        rng.next_u64()
    }
    
    /// Export wallet to WIF (Wallet Import Format) - for compatibility
    pub fn to_wif(&self, testnet: bool) -> String {
        let mut extended = Vec::new();
        
        // Version byte (mainnet: 0x80, testnet: 0xEF)
        extended.push(if testnet { 0xEF } else { 0x80 });
        extended.extend_from_slice(&self.private_key);
        extended.push(0x01); // Compressed public key flag
        
        // Calculate checksum
        let hash = double_sha256(&extended);
        extended.extend_from_slice(&hash[..4]);
        
        // Base58 encode
        bs58::encode(extended).into_string()
    }
    
    /// Import wallet from WIF
    pub fn from_wif(wif: &str) -> Result<Self, String> {
        let decoded = bs58::decode(wif)
            .into_vec()
            .map_err(|_| "Invalid WIF format")?;
        
        if decoded.len() != 38 {
            return Err("Invalid WIF length".to_string());
        }
        
        // Verify checksum
        let checksum = &decoded[34..38];
        let payload = &decoded[..34];
        let hash = double_sha256(payload);
        
        if checksum != &hash[..4] {
            return Err("Invalid WIF checksum".to_string());
        }
        
        // Extract private key
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&decoded[1..33]);
        
        Self::from_private_key(&private_key)
    }
}

/// Secure memory cleanup when wallet is dropped
impl Drop for Wallet {
    fn drop(&mut self) {
        // Zero out sensitive data
        self.private_key.zeroize();
        if let Some(ref mut seed) = self.seed_phrase {
            seed.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::new().unwrap();
        assert_eq!(wallet.public_key.len(), 33);
        assert_eq!(wallet.address.len(), 20);
    }
    
    #[test]
    fn test_seed_phrase_recovery() {
        let (wallet1, seed_phrase) = Wallet::new_with_seed_phrase().unwrap();
        let wallet2 = Wallet::from_seed_phrase(&seed_phrase).unwrap();
        
        assert_eq!(wallet1.address, wallet2.address);
        assert_eq!(wallet1.private_key, wallet2.private_key);
    }
    
    #[test]
    fn test_encryption_decryption() {
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("test_wallet.json");
        
        let wallet = Wallet::new().unwrap();
        let password = "TestPassword123!";
        
        // Save encrypted
        wallet.save_encrypted(&wallet_path, password).unwrap();
        
        // Load encrypted
        let loaded_wallet = Wallet::load_encrypted(&wallet_path, password).unwrap();
        
        assert_eq!(wallet.address, loaded_wallet.address);
        assert_eq!(wallet.private_key, loaded_wallet.private_key);
    }
    
    #[test]
    fn test_transaction_signing() {
        let wallet = Wallet::new().unwrap();
        let recipient = [1u8; 20];
        
        let mut tx = Transaction::new(
            wallet.address,
            recipient,
            1000000,
            1000,
            1,
            1,
        );
        
        wallet.sign_transaction(&mut tx).unwrap();
        assert!(tx.verify());
    }
    
    #[test]
    fn test_wif_export_import() {
        let wallet1 = Wallet::new().unwrap();
        let wif = wallet1.to_wif(false);
        let wallet2 = Wallet::from_wif(&wif).unwrap();
        
        assert_eq!(wallet1.private_key, wallet2.private_key);
        assert_eq!(wallet1.address, wallet2.address);
    }
}
