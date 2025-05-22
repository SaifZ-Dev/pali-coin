use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::error::Error;
use log::{warn, info, debug};
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher}};
use argon2::password_hash::Output;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::KeyInit;
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};
use bip39::{Language, Mnemonic, MnemonicType};
use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
use secp256k1::rand::rngs::OsRng as Secp256k1OsRng;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;

// Constants for security parameters
const ARGON2_MEMORY_COST: u32 = 65536; // 64MB
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const KEY_ROTATION_SECONDS: u64 = 300; // 5 minutes
const MAX_ENCRYPTION_ATTEMPTS: usize = 5;
const LOCKOUT_THRESHOLD: usize = 3;
const LOCKOUT_DURATION_SECONDS: u64 = 300; // 5 minutes

// Security metrics
static FAILED_DECRYPTION_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static LAST_FAILED_ATTEMPT: AtomicU64 = AtomicU64::new(0);

// Define a structure for the encrypted wallet with enhanced metadata
#[derive(Serialize, Deserialize)]
pub struct EncryptedWallet {
    pub salt: String,
    pub nonce: String,
    pub encrypted_data: String,
    pub version: u32,                  // For migration purposes
    pub kdf_memory: u32,               // Key derivation memory parameter
    pub kdf_time: u32,                 // Key derivation time parameter
    pub kdf_parallelism: u32,          // Key derivation parallelism parameter
    pub encryption_algorithm: String,  // Algorithm used
    pub created_at: u64,               // Timestamp when wallet was created
    pub last_accessed: u64,            // Timestamp when wallet was last accessed
    pub mac: String,                   // Message Authentication Code for extra verification
}

// WalletStatus is used to track the state of a wallet
#[derive(Debug, Clone, PartialEq)]
pub enum WalletStatus {
    Created,
    Unlocked,
    Locked,
    TemporarilyLocked,
}

// Custom serialization for byte arrays
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Wallet {
    #[serde(with = "hex_array_32")]
    pub private_key: [u8; 32],
    #[serde(with = "hex_array_33")]
    pub public_key: [u8; 33],
    #[serde(with = "hex_array_20")]
    pub address: [u8; 20],
    #[serde(skip)]
    pub status: WalletStatus,
    #[serde(skip)]
    pub last_unlocked: u64,
    #[serde(skip)]
    pub unlock_duration: u64, // How long the wallet remains unlocked
}

// Custom serialization modules for different size byte arrays
mod hex_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde::de::Error;

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(Error::custom)?;
        if bytes.len() != 32 {
            return Err(Error::custom(format!("Expected 32 bytes, got {}", bytes.len())));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}

mod hex_array_33 {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde::de::Error;

    pub fn serialize<S>(bytes: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(Error::custom)?;
        if bytes.len() != 33 {
            return Err(Error::custom(format!("Expected 33 bytes, got {}", bytes.len())));
        }
        let mut array = [0u8; 33];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}

mod hex_array_20 {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde::de::Error;

    pub fn serialize<S>(bytes: &[u8; 20], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(Error::custom)?;
        if bytes.len() != 20 {
            return Err(Error::custom(format!("Expected 20 bytes, got {}", bytes.len())));
        }
        let mut array = [0u8; 20];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}

impl Wallet {
    pub fn new() -> Self {
        // Create a proper secp256k1 context
        let secp = Secp256k1::new();
        
        // Generate a random private key
        let (secret_key, public_key) = secp.generate_keypair(&mut Secp256k1OsRng);
        
        // Convert to bytes
        let private_key = secret_key.secret_bytes();
        let public_key_bytes = public_key.serialize();
        
        // Generate address from public key using RIPEMD160(SHA256(public_key))
        // This is the same approach used by Bitcoin
        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&public_key_bytes);
        let sha256_hash = sha256_hasher.finalize();
        
        let mut ripemd_hasher = Ripemd160::new();
        ripemd_hasher.update(sha256_hash);
        let ripemd_hash = ripemd_hasher.finalize();
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&ripemd_hash);
        
        // Create wallet with enhanced status tracking
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Wallet {
            private_key,
            public_key: public_key_bytes,
            address,
            status: WalletStatus::Created,
            last_unlocked: current_time,
            unlock_duration: 30 * 60, // Default: 30 minutes unlock duration
        }
    }
    
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        // Create a proper secp256k1 context
        let secp = Secp256k1::new();
        
        // Recreate the secret key from bytes
        let secret_key = SecretKey::from_slice(private_key)
            .expect("Invalid private key");
        
        // Derive the public key
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes = public_key.serialize();
        
        // Generate address from public key using RIPEMD160(SHA256(public_key))
        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&public_key_bytes);
        let sha256_hash = sha256_hasher.finalize();
        
        let mut ripemd_hasher = Ripemd160::new();
        ripemd_hasher.update(sha256_hash);
        let ripemd_hash = ripemd_hasher.finalize();
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&ripemd_hash);
        
        // Create wallet with enhanced status tracking
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Wallet {
            private_key: *private_key,
            public_key: public_key_bytes,
            address,
            status: WalletStatus::Created,
            last_unlocked: current_time,
            unlock_duration: 30 * 60, // Default: 30 minutes unlock duration
        }
    }
    
    // Insecure save - only for development
    pub fn save(&self, path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        warn!("SECURITY WARNING: Saving wallet without encryption. Use save_encrypted for better security.");
        let json = serde_json::to_string(&self)?;
        fs::write(path, json)?;
        Ok(())
    }
    
    // Insecure load - only for development
    pub fn load(path: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        warn!("SECURITY WARNING: Loading wallet without encryption. Use load_encrypted for better security.");
        let json = fs::read_to_string(path)?;
        let mut wallet: Wallet = serde_json::from_str(&json)?;
        
        // Initialize status tracking
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        wallet.status = WalletStatus::Created;
        wallet.last_unlocked = current_time;
        wallet.unlock_duration = 30 * 60;
        
        Ok(wallet)
    }
    
    // Sign generic data with enhanced security checks
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // Check if wallet is in a valid state for signing
        self.check_wallet_state()?;
        
        // Create a proper secp256k1 context
        let secp = Secp256k1::new();
        
        // Create a message by hashing the data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        // Convert hash to a message
        let message = Message::from_digest_slice(&hash)
            .map_err(|_| "Failed to create message from hash")?;
        
        // Recreate the secret key from bytes
        let secret_key = SecretKey::from_slice(&self.private_key)
            .map_err(|_| "Invalid private key")?;
        
        // Sign the message with enhanced security
        let signature = secp.sign_ecdsa(&message, &secret_key);
        
        // Convert to compact signature format
        Ok(signature.serialize_compact().to_vec())
    }
    
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        // Create a proper secp256k1 context
        let secp = Secp256k1::new();
        
        // Create a message by hashing the data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        // Convert hash to a message
        let message = match Message::from_digest_slice(&hash) {
            Ok(msg) => msg,
            Err(_) => return false,
        };
        
        // Recreate the public key from bytes
        let public_key = match PublicKey::from_slice(&self.public_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        
        // Deserialize signature
        if signature.len() != 64 {
            return false;
        }
        
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        
        let signature = match secp256k1::ecdsa::Signature::from_compact(&sig_bytes) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        
        // Verify the signature in constant time to prevent timing attacks
        secp.verify_ecdsa(&message, &signature, &public_key).is_ok()
    }
    
    // Enhanced wallet encryption with stronger parameters
    pub fn save_encrypted(&self, path: &str, password: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Verify password strength
        self.verify_password_strength(password)?;
        
        // Generate a random salt for Argon2
        let salt = SaltString::generate(&mut OsRng);
        
        // Use enhanced Argon2 parameters to derive a key from the password
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
        
        // Hash the password to derive a key
        let mut key_bytes = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key_bytes)
            .map_err(|e| format!("Password hashing failed: {}", e))?;
        
        let key = Key::from_slice(&key_bytes);
        
        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Serialize wallet data
        let wallet_data = serde_json::to_vec(&self)?;
        
        // Encrypt the wallet data
        let cipher = ChaCha20Poly1305::new(key);
        let encrypted_data = cipher.encrypt(nonce, wallet_data.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Create HMAC for additional integrity protection
        let mut mac_key = [0u8; 32];
        OsRng.fill(&mut mac_key);
        let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
            .map_err(|_| "Failed to create HMAC")?;
        mac.update(&encrypted_data);
        let mac_result = mac.finalize().into_bytes();
        let mac_hex = hex::encode(mac_result);
        
        // Get current timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Create the enhanced encrypted wallet structure
        let encrypted_wallet = EncryptedWallet {
            salt: salt.as_str().to_string(),
            nonce: hex::encode(nonce_bytes),
            encrypted_data: hex::encode(encrypted_data),
            version: 2, // Version 2 with enhanced security
            kdf_memory: ARGON2_MEMORY_COST,
            kdf_time: ARGON2_TIME_COST,
            kdf_parallelism: ARGON2_PARALLELISM,
            encryption_algorithm: "ChaCha20Poly1305".to_string(),
            created_at: current_time,
            last_accessed: current_time,
            mac: mac_hex,
        };
        
        // Serialize and save to file
        let json = serde_json::to_string(&encrypted_wallet)?;
        fs::write(path, json)?;
        
        // Zero out sensitive data
        key_bytes.zeroize();
        mac_key.zeroize();
        
        info!("Wallet encrypted and saved successfully at {}", path);
        Ok(())
    }
    
    // Load wallet from encrypted file with enhanced security
    pub fn load_encrypted(path: &str, password: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Check for lockout due to failed attempts
        check_brute_force_lockout()?;
        
        // Read encrypted wallet from file
        let json = fs::read_to_string(path)?;
        let encrypted_wallet: EncryptedWallet = serde_json::from_str(&json)?;
        
        // Extract salt and KDF parameters
        let salt = &encrypted_wallet.salt;
        let kdf_memory = encrypted_wallet.kdf_memory.max(ARGON2_MEMORY_COST);
        let kdf_time = encrypted_wallet.kdf_time.max(ARGON2_TIME_COST);
        let kdf_parallelism = encrypted_wallet.kdf_parallelism.max(ARGON2_PARALLELISM);
        
        // Configure Argon2 with proper parameters
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                kdf_memory,
                kdf_time,
                kdf_parallelism,
                Some(32)
            ).map_err(|e| format!("Invalid Argon2 parameters: {}", e))?
        );
        
        // Derive key from password
        let mut key_bytes = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key_bytes)
            .map_err(|e| format!("Password verification failed: {}", e))?;
        
        let key = Key::from_slice(&key_bytes);
        
        // Extract nonce
        let nonce_bytes = hex::decode(&encrypted_wallet.nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Extract encrypted data
        let encrypted_data = hex::decode(&encrypted_wallet.encrypted_data)?;
        
        // Verify MAC first if available
        if !encrypted_wallet.mac.is_empty() {
            let mac_bytes = hex::decode(&encrypted_wallet.mac)?;
            let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
                .map_err(|_| "Failed to create HMAC")?;
            mac.update(&encrypted_data);
            let result = mac.finalize().into_bytes();
            
            // Constant-time comparison to prevent timing attacks
            if !bool::from(result.ct_eq(&mac_bytes)) {
                record_failed_attempt();
                return Err("MAC verification failed: wallet file may be corrupted or tampered with".into());
            }
        }
        
        // Decrypt the wallet data with error handling
        let cipher = ChaCha20Poly1305::new(key);
        let wallet_data = match cipher.decrypt(nonce, encrypted_data.as_ref()) {
            Ok(data) => data,
            Err(_) => {
                record_failed_attempt();
                return Err("Invalid password or corrupted wallet file".into());
            }
        };
        
        // Deserialize wallet
        let mut wallet: Wallet = serde_json::from_slice(&wallet_data)?;
        
        // Update wallet state
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        wallet.status = WalletStatus::Unlocked;
        wallet.last_unlocked = current_time;
        
        // Zero out sensitive data
        key_bytes.zeroize();
        
        // Update last accessed timestamp
        if let Some(db) = path.strip_suffix(".json") {
            if let Ok(json) = fs::read_to_string(path) {
                if let Ok(mut encrypted_wallet) = serde_json::from_str::<EncryptedWallet>(&json) {
                    encrypted_wallet.last_accessed = current_time;
                    if let Ok(updated_json) = serde_json::to_string(&encrypted_wallet) {
                        let _ = fs::write(path, updated_json); // Ignore errors here
                    }
                }
            }
        }
        
        info!("Wallet unlocked successfully");
        Ok(wallet)
    }
    
    // Generate a new wallet with a seed phrase
    pub fn new_with_seed_phrase() -> (Self, String) {
        // Generate random mnemonic with 24 words (256 bits of entropy)
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        
        // Get the phrase as a string
        let phrase = mnemonic.to_string();
        
        // Generate seed from mnemonic
        let seed = mnemonic.to_seed("");
        
        // Use first 32 bytes as private key
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&seed[0..32]);
        
        // Derive the wallet with ECDSA
        let secp = Secp256k1::new();
        
        let secret_key = SecretKey::from_slice(&private_key)
            .expect("Invalid private key from seed");
        
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes = public_key.serialize();
        
        // Generate address from public key (RIPEMD160(SHA256(pubkey)))
        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&public_key_bytes);
        let sha256_hash = sha256_hasher.finalize();
        
        let mut ripemd_hasher = Ripemd160::new();
        ripemd_hasher.update(sha256_hash);
        let ripemd_hash = ripemd_hasher.finalize();
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&ripemd_hash);
        
        // Get current time for wallet status
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let wallet = Wallet {
            private_key,
            public_key: public_key_bytes,
            address,
            status: WalletStatus::Created,
            last_unlocked: current_time,
            unlock_duration: 30 * 60,
        };
        
        (wallet, phrase)
    }
    
    // Recover a wallet from a seed phrase
    pub fn from_seed_phrase(phrase: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Validate and parse the mnemonic
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| format!("Invalid seed phrase: {}", e))?;
        
        // Generate seed from mnemonic
        let seed = mnemonic.to_seed("");
        
        // Use first 32 bytes as private key
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&seed[0..32]);
        
        // Derive the wallet with ECDSA
        let secp = Secp256k1::new();
        
        let secret_key = SecretKey::from_slice(&private_key)
            .map_err(|_| "Invalid private key generated from seed phrase")?;
        
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes = public_key.serialize();
        
        // Generate address from public key (RIPEMD160(SHA256(pubkey)))
        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&public_key_bytes);
        let sha256_hash = sha256_hasher.finalize();
        
        let mut ripemd_hasher = Ripemd160::new();
        ripemd_hasher.update(sha256_hash);
        let ripemd_hash = ripemd_hasher.finalize();
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&ripemd_hash);
        
        // Set wallet status
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(Wallet {
            private_key,
            public_key: public_key_bytes,
            address,
            status: WalletStatus::Created,
            last_unlocked: current_time,
            unlock_duration: 30 * 60,
        })
    }
    
    // Sign a transaction with enhanced security features including replay protection
    pub fn sign_transaction(&self, tx: &mut crate::types::Transaction) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if wallet is in a valid state for signing
        self.check_wallet_state()?;
        
        // Verify that the from address matches the wallet address
        if tx.from != self.address {
            return Err("Transaction from address does not match wallet address".into());
        }
        
        // Get the transaction data to sign (includes chain_id for replay protection)
        let data = tx.data_to_sign();
        
        // Sign the data using the wallet's private key
        let signature = self.sign_data(&data)?;
        
        // Set the signature in the transaction
        tx.signature = signature;
        
        debug!("Transaction signed successfully");
        Ok(())
    }
    
    // Check if the wallet is in a valid state for signing operations
    fn check_wallet_state(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        match self.status {
            WalletStatus::Locked => {
                return Err("Wallet is locked. Please unlock it first.".into());
            },
            WalletStatus::TemporarilyLocked => {
                return Err("Wallet is temporarily locked due to security concerns.".into());
            },
            WalletStatus::Unlocked => {
                // Check if unlock period has expired
                if current_time > self.last_unlocked + self.unlock_duration {
                    return Err("Wallet unlock period has expired. Please unlock it again.".into());
                }
            },
            WalletStatus::Created => {
                // Newly created wallet is fine
            }
        }
        
        Ok(())
    }
    
    // Lock the wallet when not in use
    pub fn lock(&mut self) {
        self.status = WalletStatus::Locked;
        info!("Wallet locked");
    }
    
    // Unlock the wallet with a password
    pub fn unlock(&mut self, password: &str, path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Check for lockout due to failed attempts
        check_brute_force_lockout()?;
        
        // Read encrypted wallet from file to verify password
        let json = fs::read_to_string(path)?;
        let encrypted_wallet: EncryptedWallet = serde_json::from_str(&json)?;
        
        // Extract salt and KDF parameters
        let salt = &encrypted_wallet.salt;
        let kdf_memory = encrypted_wallet.kdf_memory.max(ARGON2_MEMORY_COST);
        let kdf_time = encrypted_wallet.kdf_time.max(ARGON2_TIME_COST);
        let kdf_parallelism = encrypted_wallet.kdf_parallelism.max(ARGON2_PARALLELISM);
        
        // Configure Argon2 with proper parameters
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                kdf_memory,
                kdf_time,
                kdf_parallelism,
                Some(32)
            ).map_err(|e| format!("Invalid Argon2 parameters: {}", e))?
        );
        
        // Derive key from password
        let mut key_bytes = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key_bytes)
            .map_err(|e| format!("Password verification failed: {}", e))?;
        
        let key = Key::from_slice(&key_bytes);
        
        // Extract nonce and encrypted data to verify password
        let nonce_bytes = hex::decode(&encrypted_wallet.nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted_data = hex::decode(&encrypted_wallet.encrypted_data)?;
        
        // Try to decrypt (just to verify password)
        let cipher = ChaCha20Poly1305::new(key);
        match cipher.decrypt(nonce, encrypted_data.as_ref()) {
            Ok(_) => {
                // Password is correct, update wallet state
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                    
                self.status = WalletStatus::Unlocked;
                self.last_unlocked = current_time;
                
                // Update last accessed timestamp in the file
                let mut encrypted_wallet: EncryptedWallet = serde_json::from_str(&json)?;
                encrypted_wallet.last_accessed = current_time;
                let updated_json = serde_json::to_string(&encrypted_wallet)?;
                fs::write(path, updated_json)?;
                
                info!("Wallet unlocked successfully");
                Ok(())
            },
            Err(_) => {
                record_failed_attempt();
                Err("Invalid password".into())
            }
        }
    }
    
    // Verify password strength
    fn verify_password_strength(&self, password: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        if password.len() < 12 {
            return Err("Password must be at least 12 characters long".into());
        }
        
        let mut has_uppercase = false;
        let mut has_lowercase = false;
        let mut has_digit = false;
        let mut has_special = false;
        
        for c in password.chars() {
            if c.is_uppercase() {
                has_uppercase = true;
            } else if c.is_lowercase() {
                has_lowercase = true;
            } else if c.is_digit(10) {
                has_digit = true;
            } else if !c.is_alphanumeric() {
                has_special = true;
            }
        }
        
        let requirements_met = [has_uppercase, has_lowercase, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();
            
        if requirements_met < 3 {
            return Err("Password must contain at least 3 of the following: uppercase letters, lowercase letters, digits, special characters".into());
        }
        
        Ok(())
    }
    
    // Change wallet password
    pub fn change_password(&self, path: &str, old_password: &str, new_password: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Verify the old password first
        let json = fs::read_to_string(path)?;
        let encrypted_wallet: EncryptedWallet = serde_json::from_str(&json)?;
        
        // Extract salt and KDF parameters
        let salt = &encrypted_wallet.salt;
        let kdf_memory = encrypted_wallet.kdf_memory.max(ARGON2_MEMORY_COST);
        let kdf_time = encrypted_wallet.kdf_time.max(ARGON2_TIME_COST);
        let kdf_parallelism = encrypted_wallet.kdf_parallelism.max(ARGON2_PARALLELISM);
        
        // Configure Argon2 with proper parameters
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                kdf_memory,
                kdf_time,
                kdf_parallelism,
                Some(32)
            ).map_err(|e| format!("Invalid Argon2 parameters: {}", e))?
        );
        
        // Derive key from old password
        let mut key_bytes = [0u8; 32];
        argon2.hash_password_into(old_password.as_bytes(), salt.as_bytes(), &mut key_bytes)
            .map_err(|e| format!("Password verification failed: {}", e))?;
        
        let key = Key::from_slice(&key_bytes);
        
        // Extract nonce and encrypted data to verify password
        let nonce_bytes = hex::decode(&encrypted_wallet.nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted_data = hex::decode(&encrypted_wallet.encrypted_data)?;
        
        // Try to decrypt with old password
        let cipher = ChaCha20Poly1305::new(key);
        let wallet_data = match cipher.decrypt(nonce, encrypted_data.as_ref()) {
            Ok(data) => data,
            Err(_) => {
                record_failed_attempt();
                return Err("Invalid old password".into());
            }
        };
        
        // Old password is correct, verify strength of new password
        self.verify_password_strength(new_password)?;
        
        // Generate a new salt for Argon2
        let new_salt = SaltString::generate(&mut OsRng);
        
        // Use enhanced Argon2 parameters to derive a key from the new password
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
        
        // Hash the new password to derive a key
        let mut new_key_bytes = [0u8; 32];
        argon2.hash_password_into(new_password.as_bytes(), new_salt.as_str().as_bytes(), &mut new_key_bytes)
            .map_err(|e| format!("Password hashing failed: {}", e))?;
        
        let new_key = Key::from_slice(&new_key_bytes);
        
        // Generate a new random nonce
        let mut new_nonce_bytes = [0u8; 12];
        OsRng.fill(&mut new_nonce_bytes);
        let new_nonce = Nonce::from_slice(&new_nonce_bytes);
        
        // Encrypt the wallet data with the new key
        let new_cipher = ChaCha20Poly1305::new(new_key);
        let new_encrypted_data = new_cipher.encrypt(new_nonce, wallet_data.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Create HMAC for additional integrity protection
        let mut mac = Hmac::<Sha256>::new_from_slice(&new_key_bytes)
            .map_err(|_| "Failed to create HMAC")?;
        mac.update(&new_encrypted_data);
        let mac_result = mac.finalize().into_bytes();
        let mac_hex = hex::encode(mac_result);
        
        // Get current timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Create the enhanced encrypted wallet structure
        let new_encrypted_wallet = EncryptedWallet {
            salt: new_salt.as_str().to_string(),
            nonce: hex::encode(new_nonce_bytes),
            encrypted_data: hex::encode(new_encrypted_data),
            version: 2, // Version 2 with enhanced security
            kdf_memory: ARGON2_MEMORY_COST,
            kdf_time: ARGON2_TIME_COST,
            kdf_parallelism: ARGON2_PARALLELISM,
            encryption_algorithm: "ChaCha20Poly1305".to_string(),
            created_at: encrypted_wallet.created_at,
            last_accessed: current_time,
            mac: mac_hex,
        };
        
        // Serialize and save to file
        let new_json = serde_json::to_string(&new_encrypted_wallet)?;
        fs::write(path, new_json)?;
        
        // Zero out sensitive data
        key_bytes.zeroize();
        new_key_bytes.zeroize();
        
        info!("Wallet password changed successfully");
        Ok(())
    }
}

// Structure to store wallet and seed phrase together
#[derive(Serialize, Deserialize, Clone, ZeroizeOnDrop)]
struct WalletWithSeed {
    wallet: Wallet,
    seed_phrase: String,
}

// Generate a random nonce for transactions with additional entropy
pub fn generate_nonce() -> u64 {
    let mut rng = OsRng;
    let base_nonce = rng.next_u64();
    
    // Add timestamp for additional uniqueness
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    // XOR with timestamp to create final nonce
    base_nonce ^ timestamp
}

// Utility function to record failed decryption attempts
fn record_failed_attempt() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    FAILED_DECRYPTION_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
    LAST_FAILED_ATTEMPT.store(current_time, Ordering::SeqCst);
    
    warn!("Failed wallet decryption attempt recorded");
}

// Check for brute force lockout
fn check_brute_force_lockout() -> Result<(), Box<dyn Error + Send + Sync>> {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    let last_attempt = LAST_FAILED_ATTEMPT.load(Ordering::SeqCst);
    let attempts = FAILED_DECRYPTION_ATTEMPTS.load(Ordering::SeqCst);
    
    // Reset counter if lockout period has passed
    if current_time > last_attempt + LOCKOUT_DURATION_SECONDS {
        FAILED_DECRYPTION_ATTEMPTS.store(0, Ordering::SeqCst);
        return Ok(());
    }
    
    // Check if we're over threshold
    if attempts >= LOCKOUT_THRESHOLD as u64 {
        let seconds_remaining = (last_attempt + LOCKOUT_DURATION_SECONDS) - current_time;
        return Err(format!("Too many failed attempts. Please try again in {} seconds", seconds_remaining).into());
    }
    
    Ok(())
}
