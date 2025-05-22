use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::io::ErrorKind;

use rand::{thread_rng, Rng, RngCore};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use k256::ecdh::diffie_hellman;
use k256::{PublicKey as K256PublicKey, SecretKey as K256SecretKey};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use log::{debug, info, warn, error};

// Constants for security parameters
const KEY_ROTATION_SECONDS: u64 = 3600; // Rotate keys every hour
const MAX_MESSAGE_REPLAY_WINDOW: usize = 10000; // Max size of replay protection window
const HANDSHAKE_TIMEOUT_SECONDS: u64 = 30; // Handshake must complete within this time
const CHANNEL_TIMEOUT_SECONDS: u64 = 300; // Channel considered dead after 5 minutes of inactivity
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB max message size
const PROTOCOL_VERSION: u8 = 1; // For future protocol compatibility

// Message types for the secure channel protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Handshake = 1,
    HandshakeResponse = 2,
    KeyRotation = 3,
    KeyRotationAck = 4,
    Data = 5,
    Ping = 6,
    Pong = 7,
    Close = 8,
}

// Structure for channel state tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    New,
    HandshakeInitiated,
    Established,
    KeyRotating,
    Closing,
    Closed,
}

// Secure channel between peers with enhanced security features
#[derive(Debug, ZeroizeOnDrop)]
pub struct SecureChannel {
    // Identity keys
    #[zeroize(skip)]
    our_identity: SecretKey,
    #[zeroize(skip)]
    our_public_key: PublicKey,
    #[zeroize(skip)]
    peer_public_key: PublicKey,
    #[zeroize(skip)]
    peer_addr: SocketAddr,
    
    // Ephemeral keys for perfect forward secrecy
    ephemeral_secret: Option<K256SecretKey>,
    #[zeroize(skip)]
    ephemeral_public: Option<K256PublicKey>,
    #[zeroize(skip)]
    peer_ephemeral_public: Option<K256PublicKey>,
    
    // Cryptographic material
    shared_secret: Vec<u8>,
    encryption_key: [u8; 32],
    auth_key: [u8; 32],
    
    // Protocol state
    #[zeroize(skip)]
    message_counter_outgoing: u64,
    #[zeroize(skip)]
    message_counter_incoming: u64,
    #[zeroize(skip)]
    received_counters: HashMap<u64, bool>, // For replay protection
    #[zeroize(skip)]
    last_key_rotation: u64, // Timestamp of last key rotation
    #[zeroize(skip)]
    last_message_time: u64, // Timestamp of last message
    #[zeroize(skip)]
    state: ChannelState,
    #[zeroize(skip)]
    established_time: u64, // When the channel was established
    #[zeroize(skip)]
    protocol_version: u8, // Version for future upgrade path
}

// Encrypted message format
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub message_type: MessageType,
    pub protocol_version: u8,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub counter: u64,
    pub mac: Vec<u8>, // Message Authentication Code
}

// Handshake message format
#[derive(Debug, Serialize, Deserialize)]
struct HandshakeMessage {
    protocol_version: u8,
    ephemeral_public: Vec<u8>,
    identity_proof: Vec<u8>, // Signature proving control of identity key
    timestamp: u64,
}

// Channel manager to handle multiple secure channels
#[derive(Debug)]
pub struct SecureChannelManager {
    our_identity: SecretKey,
    our_public_key: PublicKey,
    channels: Arc<Mutex<HashMap<SocketAddr, SecureChannel>>>,
    #[allow(dead_code)] // This field will be used in future methods
    secp: Secp256k1<secp256k1::All>,
}

impl SecureChannel {
    // Create a new secure channel with enhanced security
    pub fn new(our_identity: &SecretKey, our_public_key: &PublicKey, 
               peer_public_key: &PublicKey, peer_addr: SocketAddr) 
               -> Result<Self, Box<dyn Error + Send + Sync>> {
        
        // Generate ephemeral keys for perfect forward secrecy
        let ephemeral_secret = K256SecretKey::random(&mut thread_rng());
        let ephemeral_public = K256PublicKey::from(&ephemeral_secret);
        
        // Initialize with zeroed encryption material
        // Real keys will be set during handshake
        let mut encryption_key = [0u8; 32];
        let mut auth_key = [0u8; 32];
        
        // Get current timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(SecureChannel {
            our_identity: *our_identity,
            our_public_key: *our_public_key,
            peer_public_key: *peer_public_key,
            peer_addr,
            ephemeral_secret: Some(ephemeral_secret),
            ephemeral_public: Some(ephemeral_public),
            peer_ephemeral_public: None,
            shared_secret: Vec::new(),
            encryption_key,
            auth_key,
            message_counter_outgoing: 0,
            message_counter_incoming: 0,
            received_counters: HashMap::with_capacity(100),
            last_key_rotation: current_time,
            last_message_time: current_time,
            state: ChannelState::New,
            established_time: 0,
            protocol_version: PROTOCOL_VERSION,
        })
    }
    
    // Initiate the handshake process
    pub fn initiate_handshake(&mut self) -> Result<EncryptedMessage, Box<dyn Error + Send + Sync>> {
        if self.state != ChannelState::New {
            return Err("Cannot initiate handshake: channel not in NEW state".into());
        }
        
        // Create ephemeral key if not present
        if self.ephemeral_public.is_none() {
            let ephemeral_secret = K256SecretKey::random(&mut thread_rng());
            let ephemeral_public = K256PublicKey::from(&ephemeral_secret);
            self.ephemeral_secret = Some(ephemeral_secret);
            self.ephemeral_public = Some(ephemeral_public);
        }
        
        let ephemeral_public_bytes = self.ephemeral_public
            .as_ref()
            .ok_or("No ephemeral public key")?
            .to_sec1_bytes()
            .to_vec();
        
        // Create identity proof (sign ephemeral key with identity key)
        let secp = Secp256k1::new();
        let mut hasher = Sha256::new();
        hasher.update(&ephemeral_public_bytes);
        let message = Message::from_digest_slice(&hasher.finalize())?;
        let identity_proof = secp.sign_ecdsa(&message, &self.our_identity).serialize_compact().to_vec();
        
        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Create handshake message
        let handshake_message = HandshakeMessage {
            protocol_version: self.protocol_version,
            ephemeral_public: ephemeral_public_bytes,
            identity_proof,
            timestamp,
        };
        
        // Serialize the handshake message
        let plaintext = bincode::serialize(&handshake_message)?;
        
        // For initial handshake, we use a temporary encryption scheme based on
        // the long-term public key, since we don't have a shared secret yet
        let temp_shared_key = self.derive_temporary_key()?;
        
        // Create temporary cipher with derived key
        let key = Key::from_slice(&temp_shared_key);
        let cipher = ChaCha20Poly1305::new(key);
        
        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the handshake message
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("Handshake encryption failed: {}", e))?;
            
        // Create HMAC for the message
        let mut mac = Hmac::<Sha256>::new_from_slice(&temp_shared_key)
            .map_err(|_| "Failed to create HMAC")?;
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);
        mac.update(&[MessageType::Handshake as u8]);
        mac.update(&self.protocol_version.to_le_bytes());
        let mac_result = mac.finalize().into_bytes().to_vec();
        
        // Update state
        self.state = ChannelState::HandshakeInitiated;
        self.last_message_time = timestamp;
        
        // Create encrypted message
        Ok(EncryptedMessage {
            message_type: MessageType::Handshake,
            protocol_version: self.protocol_version,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            counter: 0, // No counter for handshake
            mac: mac_result,
        })
    }
    
    // Process a received handshake message
    pub fn process_handshake(&mut self, msg: &EncryptedMessage) -> Result<Option<EncryptedMessage>, Box<dyn Error + Send + Sync>> {
        // Verify message type
        if msg.message_type != MessageType::Handshake && msg.message_type != MessageType::HandshakeResponse {
            return Err("Invalid message type for handshake processing".into());
        }
        
        // For handshake, we use a temporary encryption scheme
        let temp_shared_key = self.derive_temporary_key()?;
        
        // Verify MAC first
        let mut mac = Hmac::<Sha256>::new_from_slice(&temp_shared_key)
            .map_err(|_| "Failed to create HMAC")?;
        mac.update(&msg.nonce);
        mac.update(&msg.ciphertext);
        mac.update(&[msg.message_type as u8]);
        mac.update(&msg.protocol_version.to_le_bytes());
        
        // Use constant-time comparison for MAC verification
        if !mac.verify_slice(&msg.mac).is_ok() {
            return Err("Invalid MAC in handshake message".into());
        }
        
        // Create temporary cipher with derived key
        let key = Key::from_slice(&temp_shared_key);
        let cipher = ChaCha20Poly1305::new(key);
        
        // Decrypt the handshake message
        let nonce = Nonce::from_slice(&msg.nonce);
        let plaintext = cipher.decrypt(nonce, msg.ciphertext.as_ref())
            .map_err(|_| "Handshake decryption failed")?;
            
        // Deserialize handshake message
        let handshake_message: HandshakeMessage = bincode::deserialize(&plaintext)?;
        
        // Verify protocol version compatibility
        if handshake_message.protocol_version > self.protocol_version {
            return Err(format!("Unsupported protocol version: {}", handshake_message.protocol_version).into());
        }
        
        // Verify timestamp is recent
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        if current_time - handshake_message.timestamp > HANDSHAKE_TIMEOUT_SECONDS {
            return Err("Handshake message expired".into());
        }
        
        // Get peer's ephemeral public key
        let peer_ephemeral_public = K256PublicKey::from_sec1_bytes(&handshake_message.ephemeral_public)
            .map_err(|_| "Invalid ephemeral public key")?;
            
        // Verify the identity proof
        let secp = Secp256k1::new();
        let mut hasher = Sha256::new();
        hasher.update(&handshake_message.ephemeral_public);
        let message = Message::from_digest_slice(&hasher.finalize())?;
        let signature = secp256k1::ecdsa::Signature::from_compact(&handshake_message.identity_proof)
            .map_err(|_| "Invalid signature format")?;
            
        if !secp.verify_ecdsa(&message, &signature, &self.peer_public_key).is_ok() {
            return Err("Invalid identity proof in handshake".into());
        }
        
        // Store peer's ephemeral public key
        self.peer_ephemeral_public = Some(peer_ephemeral_public);
        
        // Derive the actual shared secret now that we have peer's ephemeral key
        self.derive_shared_secret()?;
        
        // If this is an initial handshake, respond with our own handshake
        let response = if msg.message_type == MessageType::Handshake {
            if self.state != ChannelState::New {
                return Err("Unexpected handshake message".into());
            }
            
            // Create our handshake response
            let ephemeral_public_bytes = self.ephemeral_public
                .as_ref()
                .ok_or("No ephemeral public key")?
                .to_sec1_bytes()
                .to_vec();
            
            // Create identity proof
            let mut hasher = Sha256::new();
            hasher.update(&ephemeral_public_bytes);
            let message = Message::from_digest_slice(&hasher.finalize())?;
            let identity_proof = secp.sign_ecdsa(&message, &self.our_identity).serialize_compact().to_vec();
            
            // Create handshake response message
            let response_message = HandshakeMessage {
                protocol_version: self.protocol_version,
                ephemeral_public: ephemeral_public_bytes,
                identity_proof,
                timestamp: current_time,
            };
            
            // Serialize the handshake response
            let plaintext = bincode::serialize(&response_message)?;
            
            // Encrypt with our newly derived shared secret
            let key = Key::from_slice(&self.encryption_key);
            let cipher = ChaCha20Poly1305::new(key);
            
            // Generate a random nonce
            let mut nonce_bytes = [0u8; 12];
            thread_rng().fill(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            
            // Encrypt the response
            let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
                .map_err(|e| format!("Response encryption failed: {}", e))?;
                
            // Create HMAC for the message
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.auth_key)
                .map_err(|_| "Failed to create HMAC")?;
            mac.update(&nonce_bytes);
            mac.update(&ciphertext);
            mac.update(&[MessageType::HandshakeResponse as u8]);
            mac.update(&self.protocol_version.to_le_bytes());
            let mac_result = mac.finalize().into_bytes().to_vec();
            
            // Create encrypted response message
            Some(EncryptedMessage {
                message_type: MessageType::HandshakeResponse,
                protocol_version: self.protocol_version,
                nonce: nonce_bytes.to_vec(),
                ciphertext,
                counter: 0, // No counter for handshake
                mac: mac_result,
            })
        } else {
            // This is a handshake response to our initiated handshake
            if self.state != ChannelState::HandshakeInitiated {
                return Err("Unexpected handshake response".into());
            }
            None
        };
        
        // Channel is now established
        self.state = ChannelState::Established;
        self.established_time = current_time;
        self.last_message_time = current_time;
        
        // Zeroize ephemeral secret key as it's no longer needed
        if let Some(secret) = self.ephemeral_secret.take() {
            let mut _secret = secret; // Move into mutable var for zeroizing
            _secret.zeroize();
        }
        
        info!("Secure channel established with peer {}", self.peer_addr);
        Ok(response)
    }
    
    // Encrypt a message with authenticated encryption
    pub fn encrypt_message(&mut self, message_type: MessageType, message: &[u8]) 
        -> Result<EncryptedMessage, Box<dyn Error + Send + Sync>> {
        
        // Check if channel is established
        if self.state != ChannelState::Established && self.state != ChannelState::KeyRotating {
            return Err(format!("Cannot encrypt message: channel not established (state: {:?})", self.state).into());
        }
        
        // Check for message size limits
        if message.len() > MAX_MESSAGE_SIZE {
            return Err(format!("Message too large: {} bytes (max: {})", message.len(), MAX_MESSAGE_SIZE).into());
        }
        
        // Check if key rotation is needed
        self.check_key_rotation()?;
        
        // Create ChaCha20Poly1305 cipher
        let key = Key::from_slice(&self.encryption_key);
        let cipher = ChaCha20Poly1305::new(key);
        
        // Increment message counter
        let counter = self.message_counter_outgoing;
        self.message_counter_outgoing += 1;
        
        // Generate a random nonce with counter embedded for uniqueness
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill(&mut nonce_bytes[8..]);  // 4 random bytes
        nonce_bytes[0..8].copy_from_slice(&counter.to_le_bytes());  // 8 bytes for counter
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the message (ChaCha20Poly1305 includes authentication tag)
        let ciphertext = cipher.encrypt(nonce, message)
            .map_err(|e| format!("Encryption failed: {}", e))?;
            
        // Create HMAC for additional message integrity protection
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.auth_key)
            .map_err(|_| "Failed to create HMAC")?;
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);
        mac.update(&[message_type as u8]);
        mac.update(&counter.to_le_bytes());
        mac.update(&self.protocol_version.to_le_bytes());
        let mac_result = mac.finalize().into_bytes().to_vec();
        
        // Update last message time
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_message_time = current_time;
        
        // Create encrypted message
        Ok(EncryptedMessage {
            message_type,
            protocol_version: self.protocol_version,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            counter,
            mac: mac_result,
        })
    }
    
    // Decrypt and verify an encrypted message
    pub fn decrypt_message(&mut self, encrypted: &EncryptedMessage) 
        -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        
        // Check if channel is established
        if self.state != ChannelState::Established && self.state != ChannelState::KeyRotating {
            // Special cases for handshake messages
            if encrypted.message_type == MessageType::Handshake || 
               encrypted.message_type == MessageType::HandshakeResponse {
                return Err("Handshake messages should be processed with process_handshake".into());
            }
            return Err(format!("Cannot decrypt message: channel not established (state: {:?})", self.state).into());
        }
        
        // Verify MAC first before any decryption attempt
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.auth_key)
            .map_err(|_| "Failed to create HMAC")?;
        mac.update(&encrypted.nonce);
        mac.update(&encrypted.ciphertext);
        mac.update(&[encrypted.message_type as u8]);
        mac.update(&encrypted.counter.to_le_bytes());
        mac.update(&encrypted.protocol_version.to_le_bytes());
        
        // Use constant-time comparison for MAC verification to prevent timing attacks
        if !mac.verify_slice(&encrypted.mac).is_ok() {
            return Err("Message authentication failed".into());
        }
        
        // Check for replay attacks
        if self.received_counters.contains_key(&encrypted.counter) {
            return Err("Possible replay attack detected".into());
        }
        
        // Verify counter is within acceptable range to prevent very old messages
        let max_allowed_counter_gap = 1_000_000; // Allow reasonable gaps for out-of-order messages
        if encrypted.counter + max_allowed_counter_gap < self.message_counter_incoming {
            return Err("Message counter too old".into());
        }
        
        // Update incoming counter if the new one is higher
        if encrypted.counter >= self.message_counter_incoming {
            self.message_counter_incoming = encrypted.counter + 1;
        }
        
        // Record this counter as received
        self.received_counters.insert(encrypted.counter, true);
        
        // Clean up replay protection window if it gets too large
        if self.received_counters.len() > MAX_MESSAGE_REPLAY_WINDOW {
            // Keep only the most recent counters
            let mut counters: Vec<u64> = self.received_counters.keys().cloned().collect();
            counters.sort_unstable();
            
            let cutoff = counters.len() - (MAX_MESSAGE_REPLAY_WINDOW / 2);
            for i in 0..cutoff {
                self.received_counters.remove(&counters[i]);
            }
        }
        
        // Create cipher for decryption
        let key = Key::from_slice(&self.encryption_key);
        let cipher = ChaCha20Poly1305::new(key);
        
        // Decrypt the message
        let nonce = Nonce::from_slice(&encrypted.nonce);
        let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| "Decryption failed - message may be corrupted")?;
            
        // Handle special message types
        match encrypted.message_type {
            MessageType::KeyRotation => {
                // Process key rotation in a separate method
                self.process_key_rotation(&plaintext)?;
                return Ok(Vec::new()); // Return empty response for internal messages
            },
            MessageType::KeyRotationAck => {
                // Acknowledge key rotation
                if self.state == ChannelState::KeyRotating {
                    self.state = ChannelState::Established;
                }
                return Ok(Vec::new()); // Return empty response for internal messages
            },
            MessageType::Ping => {
                // Automatically respond to pings with a pong
                let pong = self.encrypt_message(MessageType::Pong, &[])?;
                return Ok(bincode::serialize(&pong)?);
            },
            MessageType::Close => {
                // Process channel closure
                self.state = ChannelState::Closing;
                // Clean up secure channel
                let _ = self.close();
                return Ok(Vec::new());
            },
            _ => {} // Continue normal processing for other message types
        }
        
        // Update last message time
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_message_time = current_time;
        
        Ok(plaintext)
    }
    
    // Derive a temporary key for initial handshake encryption
    fn derive_temporary_key(&self) -> Result<[u8; 32], Box<dyn Error + Send + Sync>> {
        // Convert secp256k1 keys to k256 format for ECDH
        let secret_bytes = self.our_identity.secret_bytes();
        let k256_secret = K256SecretKey::from_slice(&secret_bytes)
            .map_err(|_| "Invalid secret key for ECDH")?;
            
        let peer_pubkey_bytes = self.peer_public_key.serialize();
        let k256_public = K256PublicKey::from_sec1_bytes(&peer_pubkey_bytes)
            .map_err(|_| "Invalid public key for ECDH")?;
            
        // Perform ECDH with long-term keys
        let scalar = k256_secret.to_nonzero_scalar();
        let point = k256_public.as_affine();
        let shared_secret = diffie_hellman(scalar, point);
        
        // Derive temporary encryption key using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(b"temp_encryption_key");
        hasher.update(shared_secret.raw_secret_bytes());
        
        // Add context for domain separation
        hasher.update(&self.our_public_key.serialize());
        hasher.update(&self.peer_public_key.serialize());
        
        let mut temp_key = [0u8; 32];
        temp_key.copy_from_slice(&hasher.finalize());
        
        Ok(temp_key)
    }
    
    // Derive shared secret from ephemeral and identity keys
    fn derive_shared_secret(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Get our ephemeral secret key
        let ephemeral_secret = self.ephemeral_secret
            .as_ref()
            .ok_or("No ephemeral secret key available")?;
            
        // Get peer's ephemeral public key
        let peer_ephemeral_public = self.peer_ephemeral_public
            .as_ref()
            .ok_or("No peer ephemeral public key available")?;
            
        // Perform X25519 ECDH key agreement
        let scalar = ephemeral_secret.to_nonzero_scalar();
        let point = peer_ephemeral_public.as_affine();
        let ephemeral_shared_secret = diffie_hellman(scalar, point);
        
        // Convert secp256k1 identity keys for additional ECDH
        let secret_bytes = self.our_identity.secret_bytes();
        let k256_secret = K256SecretKey::from_slice(&secret_bytes)
            .map_err(|_| "Invalid secret key for ECDH")?;
            
        let peer_pubkey_bytes = self.peer_public_key.serialize();
        let k256_public = K256PublicKey::from_sec1_bytes(&peer_pubkey_bytes)
            .map_err(|_| "Invalid public key for ECDH")?;
            
        // Perform identity ECDH
        let id_scalar = k256_secret.to_nonzero_scalar();
        let id_point = k256_public.as_affine();
        let identity_shared_secret = diffie_hellman(id_scalar, id_point);
        
        // Combined shared secret calculation
        let mut hasher = Sha256::new();
        hasher.update(b"secure_channel_v1");
        hasher.update(ephemeral_shared_secret.raw_secret_bytes());
        hasher.update(identity_shared_secret.raw_secret_bytes());
        
        // Add context for domain separation
        hasher.update(&self.our_public_key.serialize());
        hasher.update(&self.peer_public_key.serialize());
        
        // Record the combined shared secret
        let shared_bytes = hasher.finalize();
        self.shared_secret = shared_bytes.to_vec();
        
        // Derive encryption key
        let mut enc_hasher = Sha256::new();
        enc_hasher.update(b"encryption");
        enc_hasher.update(&self.shared_secret);
        self.encryption_key.copy_from_slice(&enc_hasher.finalize());
        
        // Derive authentication key (separate from encryption key)
        let mut auth_hasher = Sha256::new();
        auth_hasher.update(b"authentication");
        auth_hasher.update(&self.shared_secret);
        self.auth_key.copy_from_slice(&auth_hasher.finalize());
        
        Ok(())
    }
    
    // Check if key rotation is needed and initiate if necessary
    fn check_key_rotation(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        // Rotate keys if they're too old
        if current_time - self.last_key_rotation > KEY_ROTATION_SECONDS && 
           self.state == ChannelState::Established {
            self.initiate_key_rotation()?;
        }
        
        Ok(())
    }
    
    // Initiate key rotation for perfect forward secrecy
    fn initiate_key_rotation(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Generate new ephemeral key pair
        let new_ephemeral_secret = K256SecretKey::random(&mut thread_rng());
        let new_ephemeral_public = K256PublicKey::from(&new_ephemeral_secret);
        
        // Store new ephemeral keys
        self.ephemeral_secret = Some(new_ephemeral_secret);
        self.ephemeral_public = Some(new_ephemeral_public);
        
        // Create key rotation message with new public key
        let ephemeral_public_bytes = new_ephemeral_public.to_sec1_bytes();
        
        // Send key rotation request to peer
        let _ = self.encrypt_message(MessageType::KeyRotation, &ephemeral_public_bytes)?;
        
        // Update state
        self.state = ChannelState::KeyRotating;
        
        Ok(())
    }
    
    // Process a key rotation message from peer
    fn process_key_rotation(&mut self, message: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Extract peer's new ephemeral public key
        let peer_ephemeral_public = K256PublicKey::from_sec1_bytes(message)
            .map_err(|_| "Invalid ephemeral public key in key rotation")?;
            
        // Store peer's new ephemeral key
        self.peer_ephemeral_public = Some(peer_ephemeral_public);
        
        // Generate new ephemeral key if we haven't already
        if self.ephemeral_secret.is_none() {
            let new_ephemeral_secret = K256SecretKey::random(&mut thread_rng());
            let new_ephemeral_public = K256PublicKey::from(&new_ephemeral_secret);
            
            self.ephemeral_secret = Some(new_ephemeral_secret);
            self.ephemeral_public = Some(new_ephemeral_public);
            
            // Send our new public key in response
            let ephemeral_public_bytes = new_ephemeral_public.to_sec1_bytes();
            let _ = self.encrypt_message(MessageType::KeyRotation, &ephemeral_public_bytes)?;
        }
        
        // Derive new shared secret
        self.derive_shared_secret()?;
        
        // Send acknowledgement
        let _ = self.encrypt_message(MessageType::KeyRotationAck, &[])?;
        
        // Update key rotation timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_key_rotation = current_time;
        
        // Update state
        self.state = ChannelState::Established;
        
        info!("Key rotation completed for peer {}", self.peer_addr);
        Ok(())
    }
    
    // Generate and encrypt a ping message
    pub fn ping(&mut self) -> Result<EncryptedMessage, Box<dyn Error + Send + Sync>> {
        // Simple ping with timestamp for RTT measurement
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let timestamp = current_time.to_le_bytes();
        
        self.encrypt_message(MessageType::Ping, &timestamp)
    }
    
    // Check if connection has timed out
    pub fn has_timed_out(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        current_time - self.last_message_time > CHANNEL_TIMEOUT_SECONDS
    }
    
    // Close the secure channel
    pub fn close(&mut self) -> Result<Option<EncryptedMessage>, Box<dyn Error + Send + Sync>> {
        // Generate close message if channel is still active
        let close_message = if self.state == ChannelState::Established || 
                               self.state == ChannelState::KeyRotating {
            // Send close notification
            let msg = self.encrypt_message(MessageType::Close, &[])?;
            Some(msg)
        } else {
            None
        };
        
        // Clean up secure state
        self.state = ChannelState::Closed;
        self.shared_secret.zeroize();
        self.encryption_key.zeroize();
        self.auth_key.zeroize();
        
        // Clean up ephemeral keys
        if let Some(mut secret) = self.ephemeral_secret.take() {
            secret.zeroize();
        }
        
        Ok(close_message)
    }
    
    // Get current state of the channel
    pub fn get_state(&self) -> ChannelState {
        self.state
    }
    
    // Get peer address
    pub fn get_peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
    
    // Get establishment time
    pub fn get_established_time(&self) -> u64 {
        self.established_time
    }
}

impl SecureChannelManager {
    pub fn new(identity: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &identity);
        
        SecureChannelManager {
            our_identity: identity,
            our_public_key: public_key,
            channels: Arc::new(Mutex::new(HashMap::new())),
            secp,
        }
    }
    
    // Establish a new secure channel with a peer
    pub fn establish_channel(&self, peer_public_key: PublicKey, peer_addr: SocketAddr) 
        -> Result<Arc<Mutex<SecureChannel>>, Box<dyn Error + Send + Sync>> {
        
        // Check if we already have a channel with this peer
        let existing_channel = {
            let channels = self.channels.lock().map_err(|_| "Failed to lock channels")?;
            channels.get(&peer_addr).cloned()
        };
        
        if let Some(channel) = existing_channel {
            return Ok(channel);
        }
        
        // Create new secure channel
        let channel = SecureChannel::new(&self.our_identity, &self.our_public_key, &peer_public_key, peer_addr)?;
        let channel_arc = Arc::new(Mutex::new(channel));
        
        // Store the channel
        let mut channels = self.channels.lock().map_err(|_| "Failed to lock channels")?;
        channels.insert(peer_addr, channel_arc.clone());
        
        Ok(channel_arc)
    }
    
    // Remove a secure channel
    pub fn remove_channel(&self, peer_addr: &SocketAddr) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut channels = self.channels.lock().map_err(|_| "Failed to lock channels")?;
        
        if let Some(channel_arc) = channels.remove(peer_addr) {
            // Properly close the channel if possible
            let mut channel = channel_arc.lock().map_err(|_| "Failed to lock channel")?;
            let _ = channel.close(); // Ignore errors during cleanup
        }
        
        Ok(())
    }
    
    // Get a secure channel for a peer
    pub fn get_channel(&self, peer_addr: &SocketAddr) -> Option<Arc<Mutex<SecureChannel>>> {
        match self.channels.lock() {
            Ok(channels) => channels.get(peer_addr).cloned(),
            Err(_) => None,
        }
    }
    
    // Clean up timed-out channels
    pub fn cleanup_channels(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut channels = self.channels.lock().map_err(|_| "Failed to lock channels")?;
        let mut to_remove = Vec::new();
        
        // Identify channels to remove
        for (addr, channel_arc) in channels.iter() {
            if let Ok(channel) = channel_arc.lock() {
                if channel.has_timed_out() || channel.get_state() == ChannelState::Closed {
                    to_remove.push(*addr);
                }
            }
        }
        
        // Remove them
        for addr in to_remove {
            if let Some(channel_arc) = channels.remove(&addr) {
                if let Ok(mut channel) = channel_arc.lock() {
                    let _ = channel.close(); // Ignore errors during cleanup
                }
            }
        }
        
        Ok(())
    }
}

// Handle cleanup of sensitive data when SecureChannel is dropped
impl Drop for SecureChannel {
    fn drop(&mut self) {
        // Zero out sensitive cryptographic material
        self.shared_secret.zeroize();
        self.encryption_key.zeroize();
        self.auth_key.zeroize();
        
        // Zero out ephemeral keys
        if let Some(mut secret) = self.ephemeral_secret.take() {
            secret.zeroize();
        }
        
        debug!("Secure channel resources cleaned up for peer {}", self.peer_addr);
    }
}
