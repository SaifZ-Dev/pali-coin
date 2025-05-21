use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use k256::ecdh::{SharedSecret, diffie_hellman};
use k256::{PublicKey as K256PublicKey, SecretKey as K256SecretKey};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

// Secure channel between peers with forward secrecy
#[derive(Debug, ZeroizeOnDrop)]
pub struct SecureChannel {
    #[zeroize(skip)]
    our_identity: SecretKey,
    #[zeroize(skip)]
    our_public_key: PublicKey,
    #[zeroize(skip)]
    peer_public_key: PublicKey,
    #[zeroize(skip)]
    peer_addr: SocketAddr,
    shared_secret: Vec<u8>,
    encryption_key: [u8; 32],
    mac_key: [u8; 32],
    message_counter_outgoing: u64,
    message_counter_incoming: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
    pub counter: u64,
}

#[derive(Debug)]
pub struct SecureChannelManager {
    our_identity: SecretKey,
    our_public_key: PublicKey,
    channels: Arc<Mutex<HashMap<SocketAddr, SecureChannel>>>,
}

impl SecureChannel {
    pub fn new(our_identity: &SecretKey, our_public_key: &PublicKey, peer_public_key: &PublicKey, peer_addr: SocketAddr) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Convert secp256k1 types to k256 types for proper ECDH
        let secret_bytes = our_identity.secret_bytes();
        let k256_secret = K256SecretKey::from_bytes(&secret_bytes.into())
            .map_err(|_| "Invalid secret key for ECDH")?;
        
        let peer_pubkey_bytes = peer_public_key.serialize();
        let k256_public = K256PublicKey::from_sec1_bytes(&peer_pubkey_bytes)
            .map_err(|_| "Invalid public key for ECDH")?;
        
        // Perform ECDH key agreement using X25519
        let shared_secret = diffie_hellman(
            k256_secret.to_nonzero_scalar(),
            k256_public.as_affine(),
        );
        
        // Get the shared secret bytes
        let shared_bytes = shared_secret.raw_secret_bytes();
        
        // Use HKDF to derive multiple keys from the shared secret
        let hkdf = Hkdf::<Sha256>::new(None, shared_bytes);
        
        // Derive encryption key
        let mut encryption_key = [0u8; 32];
        hkdf.expand(b"encryption", &mut encryption_key)
            .map_err(|_| "HKDF expansion failed for encryption key")?;
        
        // Derive MAC key
        let mut mac_key = [0u8; 32];
        hkdf.expand(b"mac", &mut mac_key)
            .map_err(|_| "HKDF expansion failed for MAC key")?;
        
        // Create the secure channel
        Ok(SecureChannel {
            our_identity: *our_identity,
            our_public_key: *our_public_key,
            peer_public_key: *peer_public_key,
            shared_secret: shared_bytes.to_vec(),
            encryption_key,
            mac_key,
            peer_addr,
            message_counter_outgoing: 0,
            message_counter_incoming: 0,
        })
    }
    
    pub fn encrypt_message(&mut self, message: &[u8]) -> Result<EncryptedMessage, Box<dyn Error + Send + Sync>> {
        // Create ChaCha20Poly1305 cipher
        let key = Key::from_slice(&self.encryption_key);
        let cipher = ChaCha20Poly1305::new(key);
        
        // Generate a nonce (using counter to ensure uniqueness)
        let nonce_value = self.message_counter_outgoing;
        self.message_counter_outgoing += 1;
        
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&nonce_value.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the message
        let ciphertext = cipher.encrypt(nonce, message)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Calculate MAC over the ciphertext for additional authentication
        let mut mac = HmacSha256::new_from_slice(&self.mac_key)
            .map_err(|_| "HMAC initialization failed")?;
        
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);
        mac.update(&nonce_value.to_le_bytes());
        
        let mac_bytes = mac.finalize().into_bytes().to_vec();
        
        Ok(EncryptedMessage {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            mac: mac_bytes,
            counter: nonce_value,
        })
    }
    
    pub fn decrypt_message(&mut self, encrypted: &EncryptedMessage) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // Check for replay attacks
        if encrypted.counter < self.message_counter_incoming {
            return Err("Potential replay attack detected".into());
        }
        
        // Verify MAC first
        let mut mac = HmacSha256::new_from_slice(&self.mac_key)
            .map_err(|_| "HMAC initialization failed")?;
        
        mac.update(&encrypted.nonce);
        mac.update(&encrypted.ciphertext);
        mac.update(&encrypted.counter.to_le_bytes());
        
        // Verify the MAC in constant time to prevent timing attacks
        mac.verify_slice(&encrypted.mac)
            .map_err(|_| "MAC verification failed - message may have been tampered with")?;
        
        // Create ChaCha20Poly1305 cipher
        let key = Key::from_slice(&self.encryption_key);
        let cipher = ChaCha20Poly1305::new(key);
        
        // Convert nonce
        let nonce = Nonce::from_slice(&encrypted.nonce);
        
        // Decrypt the message
        let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| "Decryption failed - message may be corrupted")?;
        
        // Update counter
        self.message_counter_incoming = encrypted.counter + 1;
        
        Ok(plaintext)
    }
    
    // Perform rekeying to provide perfect forward secrecy
    pub fn rekey(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Generate a new ephemeral key pair
        let secp = Secp256k1::new();
        let (ephemeral_secret, ephemeral_public) = secp.generate_keypair(&mut OsRng);
        
        // Perform another ECDH using the ephemeral key
        let ephemeral_secret_bytes = ephemeral_secret.secret_bytes();
        let k256_ephemeral_secret = K256SecretKey::from_bytes(&ephemeral_secret_bytes.into())
            .map_err(|_| "Invalid ephemeral secret key")?;
        
        let peer_pubkey_bytes = self.peer_public_key.serialize();
        let k256_peer_public = K256PublicKey::from_sec1_bytes(&peer_pubkey_bytes)
            .map_err(|_| "Invalid peer public key for rekeying")?;
        
        // Perform ECDH
        let new_shared_secret = diffie_hellman(
            k256_ephemeral_secret.to_nonzero_scalar(),
            k256_peer_public.as_affine(),
        );
        
        // Get the new shared secret
        let new_shared_bytes = new_shared_secret.raw_secret_bytes();
        
        // Combine with the current shared secret for forward secrecy
        let mut hasher = Sha256::new();
        hasher.update(&self.shared_secret);
        hasher.update(new_shared_bytes);
        let combined_secret = hasher.finalize();
        
        // Use HKDF to derive new keys
        let hkdf = Hkdf::<Sha256>::new(None, &combined_secret);
        
        // Derive new encryption key
        let mut new_encryption_key = [0u8; 32];
        hkdf.expand(b"encryption", &mut new_encryption_key)
            .map_err(|_| "HKDF expansion failed for new encryption key")?;
        
        // Derive new MAC key
        let mut new_mac_key = [0u8; 32];
        hkdf.expand(b"mac", &mut new_mac_key)
            .map_err(|_| "HKDF expansion failed for new MAC key")?;
        
        // Update keys
        self.shared_secret = combined_secret.to_vec();
        self.encryption_key = new_encryption_key;
        self.mac_key = new_mac_key;
        
        // Zero out sensitive data
        ephemeral_secret_bytes.zeroize();
        
        Ok(())
    }
}

impl SecureChannelManager {
    pub fn new() -> Self {
        // Generate our identity key
        let secp = Secp256k1::new();
        let mut rng = OsRng::default();
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);
        
        SecureChannelManager {
            our_identity: secret_key,
            our_public_key: public_key,
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    pub fn get_public_key(&self) -> PublicKey {
        self.our_public_key
    }
    
    pub fn establish_channel(&self, peer_public_key: &PublicKey, peer_addr: SocketAddr) -> Result<(), Box<dyn Error + Send + Sync>> {
        let channel = SecureChannel::new(
            &self.our_identity,
            &self.our_public_key,
            peer_public_key,
            peer_addr
        )?;
        
        self.channels.lock().unwrap().insert(peer_addr, channel);
        Ok(())
    }
    
    pub fn encrypt_message(&self, peer_addr: SocketAddr, message: &[u8]) -> Result<EncryptedMessage, Box<dyn Error + Send + Sync>> {
        let mut channels = self.channels.lock().unwrap();
        
        if let Some(channel) = channels.get_mut(&peer_addr) {
            // Perform periodic rekeying for perfect forward secrecy
            if channel.message_counter_outgoing % 100 == 0 {
                channel.rekey()?;
            }
            
            channel.encrypt_message(message)
        } else {
            Err("No secure channel established with the peer".into())
        }
    }
    
    pub fn decrypt_message(&self, peer_addr: SocketAddr, encrypted: &EncryptedMessage) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut channels = self.channels.lock().unwrap();
        
        if let Some(channel) = channels.get_mut(&peer_addr) {
            // Perform periodic rekeying for perfect forward secrecy
            if channel.message_counter_incoming % 100 == 0 {
                channel.rekey()?;
            }
            
            channel.decrypt_message(encrypted)
        } else {
            Err("No secure channel established with the peer".into())
        }
    }
    
    // Close a channel and securely erase its keys
    pub fn close_channel(&self, peer_addr: SocketAddr) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut channels = self.channels.lock().unwrap();
        channels.remove(&peer_addr);
        Ok(())
    }
}
