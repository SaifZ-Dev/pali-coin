use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::error::Error;
use log::warn;
use argon2::{Argon2, password_hash::SaltString};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use rand::Rng;
use zeroize::Zeroize;
use bip39::{Language, Mnemonic};
use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
use secp256k1::rand::rngs::OsRng as Secp256k1OsRng;

// Define a structure for the encrypted wallet
#[derive(Serialize, Deserialize)]
pub struct EncryptedWallet {
    pub salt: String,
    pub nonce: String,
    pub encrypted_data: String,
}

// Custom serialization for byte arrays
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    #[serde(with = "hex_array_32")]
    pub private_key: [u8; 32],
    #[serde(with = "hex_array_33")]
    pub public_key: [u8; 33],
    #[serde(with = "hex_array_20")]
    pub address: [u8; 20],
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
        
        // Generate address from public key (using a simple hash for now)
        // In a real implementation, you might want to use RIPEMD160(SHA256(publicKey)) like Bitcoin
        let mut hasher = Sha256::new();
        hasher.update(&public_key_bytes);
        let hash = hasher.finalize();
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[0..20]);
        
        Wallet {
            private_key,
            public_key: public_key_bytes,
            address,
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
        
        // Generate address from public key
        let mut hasher = Sha256::new();
        hasher.update(&public_key_bytes);
        let hash = hasher.finalize();
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[0..20]);
        
        Wallet {
            private_key: *private_key,
            public_key: public_key_bytes,
            address,
        }
    }
    
    pub fn save(&self, path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        warn!("Saving wallet without encryption. Use save_encrypted for better security.");
        let json = serde_json::to_string(&self)?;
        fs::write(path, json)?;
        Ok(())
    }
    
    pub fn load(path: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let json = fs::read_to_string(path)?;
        let wallet: Wallet = serde_json::from_str(&json)?;
        Ok(wallet)
    }
    
    pub fn sign_data(&self, data: &[u8]) -> Vec<u8> {
        // Create a proper secp256k1 context
        let secp = Secp256k1::new();
        
        // Create a message by hashing the data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        // Convert hash to a message
        let message = Message::from_digest_slice(&hash)
            .expect("Failed to create message from hash");
        
        // Recreate the secret key from bytes
        let secret_key = SecretKey::from_slice(&self.private_key)
            .expect("Invalid private key");
        
        // Sign the message
        let signature = secp.sign_ecdsa(&message, &secret_key);
        
        // Convert to compact signature format
        signature.serialize_compact().to_vec()
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
        
        // Verify the signature
        secp.verify_ecdsa(&message, &signature, &public_key).is_ok()
    }
    
    // Encrypt and save wallet to file with password
    pub fn save_encrypted(&self, path: &str, password: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Generate a random salt for Argon2
        let salt = SaltString::generate(&mut OsRng);
        
        // Use Argon2 to derive a key from the password
        let argon2 = Argon2::default();
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
        
        // Create the encrypted wallet structure
        let encrypted_wallet = EncryptedWallet {
            salt: salt.as_str().to_string(),
            nonce: hex::encode(nonce_bytes),
            encrypted_data: hex::encode(encrypted_data),
        };
        
        // Serialize and save to file
        let json = serde_json::to_string(&encrypted_wallet)?;
        fs::write(path, json)?;
        
        // Zero out sensitive data
        key_bytes.zeroize();
        
        Ok(())
    }
    
    // Load wallet from encrypted file with password
    pub fn load_encrypted(path: &str, password: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Read encrypted wallet from file
        let json = fs::read_to_string(path)?;
        let encrypted_wallet: EncryptedWallet = serde_json::from_str(&json)?;
        
        // Extract salt and derive key
        let salt = &encrypted_wallet.salt;
        
        let argon2 = Argon2::default();
        let mut key_bytes = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key_bytes)
            .map_err(|e| format!("Password verification failed: {}", e))?;
        
        let key = Key::from_slice(&key_bytes);
        
        // Extract nonce
        let nonce_bytes = hex::decode(&encrypted_wallet.nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Extract encrypted data
        let encrypted_data = hex::decode(&encrypted_wallet.encrypted_data)?;
        
        // Decrypt the wallet data
        let cipher = ChaCha20Poly1305::new(key);
        let wallet_data = cipher.decrypt(nonce, encrypted_data.as_ref())
            .map_err(|_| "Invalid password or corrupted wallet file")?;
        
        // Deserialize wallet
        let wallet: Wallet = serde_json::from_slice(&wallet_data)?;
        
        // Zero out sensitive data
        key_bytes.zeroize();
        
        Ok(wallet)
    }
    
    // Generate a new wallet with a seed phrase
    pub fn new_with_seed_phrase() -> (Self, String) {
        // Generate random entropy (32 bytes for 24 words)
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        
        // Create mnemonic from entropy
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Failed to generate mnemonic");
        
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
        
        // Generate address from public key
        let mut hasher = Sha256::new();
        hasher.update(&public_key_bytes);
        let hash = hasher.finalize();
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[0..20]);
        
        let wallet = Wallet {
            private_key,
            public_key: public_key_bytes,
            address,
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
        
        // Generate address from public key
        let mut hasher = Sha256::new();
        hasher.update(&public_key_bytes);
        let hash = hasher.finalize();
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[0..20]);
        
        Ok(Wallet {
            private_key,
            public_key: public_key_bytes,
            address,
        })
    }
    
    // Save wallet with seed phrase (encrypt both)
    pub fn save_with_seed_phrase(&self, path: &str, seed_phrase: &str, password: &str) 
        -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create a structure with wallet and seed phrase
        let wallet_data = WalletWithSeed {
            wallet: self.clone(),
            seed_phrase: seed_phrase.to_string(),
        };
        
        // Encrypt and save
        // Generate a random salt for Argon2
        let salt = SaltString::generate(&mut OsRng);
        
        // Use Argon2 to derive a key from the password
        let argon2 = Argon2::default();
        let mut key_bytes = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key_bytes)
            .map_err(|e| format!("Password hashing failed: {}", e))?;
        
        let key = Key::from_slice(&key_bytes);
        
        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Serialize wallet data
        let wallet_data = serde_json::to_vec(&wallet_data)?;
        
        // Encrypt the wallet data
        let cipher = ChaCha20Poly1305::new(key);
        let encrypted_data = cipher.encrypt(nonce, wallet_data.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Create the encrypted wallet structure
        let encrypted_wallet = EncryptedWallet {
            salt: salt.as_str().to_string(),
            nonce: hex::encode(nonce_bytes),
            encrypted_data: hex::encode(encrypted_data),
        };
        
        // Serialize and save to file
        let json = serde_json::to_string(&encrypted_wallet)?;
        fs::write(path, json)?;
        
        // Zero out sensitive data
        key_bytes.zeroize();
        
        Ok(())
    }
    
    // Load wallet with seed phrase
    pub fn load_with_seed_phrase(path: &str, password: &str) 
        -> Result<(Self, String), Box<dyn std::error::Error + Send + Sync>> {
        // Read encrypted wallet from file
        let json = fs::read_to_string(path)?;
        let encrypted_wallet: EncryptedWallet = serde_json::from_str(&json)?;
        
        // Extract salt and derive key
        let salt = &encrypted_wallet.salt;
        
        let argon2 = Argon2::default();
        let mut key_bytes = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key_bytes)
            .map_err(|e| format!("Password verification failed: {}", e))?;
        
        let key = Key::from_slice(&key_bytes);
        
        // Extract nonce
        let nonce_bytes = hex::decode(&encrypted_wallet.nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Extract encrypted data
        let encrypted_data = hex::decode(&encrypted_wallet.encrypted_data)?;
        
        // Decrypt the wallet data
        let cipher = ChaCha20Poly1305::new(key);
        let wallet_data = cipher.decrypt(nonce, encrypted_data.as_ref())
            .map_err(|_| "Invalid password or corrupted wallet file")?;
        
        // Deserialize wallet with seed
        let wallet_with_seed: WalletWithSeed = serde_json::from_slice(&wallet_data)?;
        
        // Zero out sensitive data
        key_bytes.zeroize();
        
        Ok((wallet_with_seed.wallet, wallet_with_seed.seed_phrase))
    }
    
    // Sign a transaction using this wallet
    pub fn sign_transaction(&self, tx: &mut crate::types::Transaction) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Verify that the from address matches the wallet address
        if tx.from != self.address {
            return Err("Transaction from address does not match wallet address".into());
        }
        
        // Get the transaction data to sign
        let data = tx.data_to_sign();
        
        // Sign the data using the wallet's private key
        let signature = self.sign_data(&data);
        
        // Set the signature in the transaction
        tx.signature = signature;
        
        Ok(())
    }
}

// Structure to store wallet and seed phrase together
#[derive(Serialize, Deserialize, Clone)]
struct WalletWithSeed {
    wallet: Wallet,
    seed_phrase: String,
}

// Generate a random nonce for transactions
pub fn generate_nonce() -> u64 {
    OsRng.next_u64()
}
