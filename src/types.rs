// src/types.rs - Bitcoin-grade cryptographic types for Pali Coin
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use secp256k1::{
    Secp256k1, Message, SecretKey, PublicKey, 
    ecdsa::{Signature, RecoverableSignature, RecoveryId}
};
use ripemd::{Ripemd160, Digest as RipemdDigest};
use std::fmt;
use chrono::{DateTime, Utc};

pub type Address = [u8; 20];
pub type Hash = [u8; 32];

/// Enhanced block header with Bitcoin-grade security
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    /// Version for protocol upgrades
    pub version: u32,
    
    /// Hash of the previous block
    pub prev_hash: Hash,
    
    /// Merkle root of all transactions in the block
    pub merkle_root: Hash,
    
    /// Block creation timestamp (Unix seconds)
    pub timestamp: u64,
    
    /// Block height in the chain
    pub height: u64,
    
    /// Mining difficulty target (leading zero bits required)
    pub difficulty_target: u32,
    
    /// Proof-of-work nonce
    pub nonce: u64,
    
    /// Number of transactions in block
    pub tx_count: u32,
    
    /// Block size in bytes (for consensus rules)
    pub block_size: u32,
}

impl Default for BlockHeader {
    fn default() -> Self {
        BlockHeader {
            version: 1,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: Utc::now().timestamp() as u64,
            height: 0,
            difficulty_target: 24, // 24 leading zero bits
            nonce: 0,
            tx_count: 0,
            block_size: 0,
        }
    }
}

/// Complete block with enhanced validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    
    /// All transactions in the block
    pub transactions: Vec<Transaction>,
    
    /// Optional zero-knowledge proof for privacy
    pub zk_proof: Option<Vec<u8>>,
    
    /// Block signature for validator consensus (future PoS)
    pub signature: Option<Vec<u8>>,
}

impl Block {
    /// Create a new block
    pub fn new(
        prev_hash: Hash,
        transactions: Vec<Transaction>,
        difficulty_target: u32,
        height: u64,
    ) -> Self {
        let tx_count = transactions.len() as u32;
        let merkle_root = Self::calculate_merkle_root(&transactions);
        
        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root,
            timestamp: Utc::now().timestamp() as u64,
            height,
            difficulty_target,
            nonce: 0,
            tx_count,
            block_size: 0, // Will be calculated when serialized
        };
        
        Block {
            header,
            transactions,
            zk_proof: None,
            signature: None,
        }
    }
    
    /// Calculate Bitcoin-style double SHA-256 hash
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        
        // Hash all header fields
        hasher.update(&self.header.version.to_be_bytes());
        hasher.update(&self.header.prev_hash);
        hasher.update(&self.header.merkle_root);
        hasher.update(&self.header.timestamp.to_be_bytes());
        hasher.update(&self.header.height.to_be_bytes());
        hasher.update(&self.header.difficulty_target.to_be_bytes());
        hasher.update(&self.header.nonce.to_be_bytes());
        hasher.update(&self.header.tx_count.to_be_bytes());
        
        // Double SHA-256 for extra security (Bitcoin standard)
        let first_hash = hasher.finalize();
        let mut second_hasher = Sha256::new();
        second_hasher.update(first_hash);
        
        let result = second_hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Verify proof-of-work meets difficulty requirement
    pub fn is_valid_proof_of_work(&self) -> bool {
        let hash = self.hash();
        meets_difficulty_target(&hash, self.header.difficulty_target)
    }
    
    /// Calculate merkle root with Bitcoin-compatible algorithm
    fn calculate_merkle_root(transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return [0; 32];
        }
        
        let mut hashes: Vec<Hash> = transactions.iter()
            .map(|tx| tx.hash())
            .collect();
        
        while hashes.len() > 1 {
            let mut new_level = Vec::new();
            
            // Process pairs of hashes
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                } else {
                    // If odd number, duplicate the last hash (Bitcoin standard)
                    hasher.update(&chunk[0]);
                }
                
                // Double SHA-256
                let first_hash = hasher.finalize();
                let mut second_hasher = Sha256::new();
                second_hasher.update(first_hash);
                
                let result = second_hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                
                new_level.push(hash);
            }
            
            hashes = new_level;
        }
        
        hashes[0]
    }
    
    /// Verify merkle root matches transactions
    pub fn verify_merkle_root(&self) -> bool {
        let calculated = Self::calculate_merkle_root(&self.transactions);
        self.header.merkle_root == calculated
    }
    
    /// Check if block is genesis block
    pub fn is_genesis(&self) -> bool {
        self.header.height == 0 && self.header.prev_hash == [0; 32]
    }
    
    /// Get coinbase transaction (first transaction if it exists)
    pub fn coinbase_transaction(&self) -> Option<&Transaction> {
        self.transactions.first().filter(|tx| tx.is_coinbase())
    }
    
    /// Comprehensive block validation
    pub fn validate(&self, prev_block: Option<&Block>) -> Result<(), String> {
        // Verify merkle root
        if !self.verify_merkle_root() {
            return Err("Invalid merkle root".to_string());
        }
        
        // Verify proof of work
        if !self.is_valid_proof_of_work() {
            return Err("Insufficient proof of work".to_string());
        }
        
        // Verify timestamp is reasonable
        let now = Utc::now().timestamp() as u64;
        if self.header.timestamp > now + 7200 { // Max 2 hours in future
            return Err("Block timestamp too far in future".to_string());
        }
        
        // Verify against previous block if provided
        if let Some(prev) = prev_block {
            if self.header.prev_hash != prev.hash() {
                return Err("Invalid previous hash".to_string());
            }
            
            if self.header.height != prev.header.height + 1 {
                return Err("Invalid block height".to_string());
            }
            
            if self.header.timestamp <= prev.header.timestamp {
                return Err("Block timestamp not after previous".to_string());
            }
        }
        
        // Validate all transactions
        for (i, tx) in self.transactions.iter().enumerate() {
            if let Err(e) = tx.validate(Some(1)) {
                return Err(format!("Transaction {} invalid: {}", i, e));
            }
        }
        
        Ok(())
    }
}

/// Enhanced transaction with full ECDSA signature recovery
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    /// Transaction version for protocol upgrades
    pub version: u32,
    
    /// Sender address (20 bytes)
    pub from: Address,
    
    /// Recipient address (20 bytes)
    pub to: Address,
    
    /// Amount to transfer (in smallest units - 1 PALI = 1,000,000 units)
    pub amount: u64,
    
    /// Transaction fee (in smallest units)
    pub fee: u64,
    
    /// Transaction nonce (prevents replay attacks)
    pub nonce: u64,
    
    /// Chain ID for replay protection across networks
    pub chain_id: u64,
    
    /// Transaction expiry timestamp (0 = no expiry)
    pub expiry: u64,
    
    /// ECDSA signature with recovery (65 bytes: 64 + recovery_id)
    pub signature: Vec<u8>,
    
    /// Sender's public key (for verification, 33 bytes compressed)
    pub public_key: Vec<u8>,
    
    /// Optional transaction data/memo
    pub data: Option<Vec<u8>>,
}

impl Transaction {
    /// Create a new transaction
    pub fn new(
        from: Address,
        to: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Self {
        Transaction {
            version: 1,
            from,
            to,
            amount,
            fee,
            nonce,
            chain_id,
            expiry: 0,
            signature: Vec::new(),
            public_key: Vec::new(),
            data: None,
        }
    }
    
    /// Create a coinbase transaction (mining reward)
    pub fn coinbase(to: Address, amount: u64, height: u64, chain_id: u64) -> Self {
        Transaction {
            version: 1,
            from: [0u8; 20],
            to,
            amount,
            fee: 0,
            nonce: height, // Use height as nonce for coinbase
            chain_id,
            expiry: 0,
            signature: Vec::new(),
            public_key: Vec::new(),
            data: Some(format!("Coinbase reward for block {}", height).into_bytes()),
        }
    }
    
    /// Set expiry time
    pub fn with_expiry(mut self, expiry_timestamp: u64) -> Self {
        self.expiry = expiry_timestamp;
        self
    }
    
    /// Set transaction data
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }
    
    /// Get data to be signed (everything except signature and public_key)
    pub fn data_to_sign(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.version.to_be_bytes());
        data.extend_from_slice(&self.from);
        data.extend_from_slice(&self.to);
        data.extend_from_slice(&self.amount.to_be_bytes());
        data.extend_from_slice(&self.fee.to_be_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.chain_id.to_be_bytes());
        
        if self.expiry > 0 {
            data.extend_from_slice(&self.expiry.to_be_bytes());
        }
        
        if let Some(ref tx_data) = self.data {
            data.extend_from_slice(tx_data);
        }
        
        data
    }
    
    /// Sign transaction with private key using ECDSA with recovery
    pub fn sign(&mut self, private_key: &SecretKey, public_key: &PublicKey) -> Result<(), String> {
        let secp = Secp256k1::new();
        let signing_data = self.data_to_sign();
        
        // Hash the signing data
        let hash = double_sha256(&signing_data);
        let message = Message::from_digest_slice(&hash)
            .map_err(|e| format!("Invalid message: {}", e))?;
        
        // Create recoverable signature
        let signature = secp.sign_ecdsa_recoverable(&message, private_key);
        
        // Serialize with recovery ID
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let mut full_signature = Vec::with_capacity(65);
        full_signature.extend_from_slice(&signature_bytes);
        full_signature.push(recovery_id.to_i32() as u8);
        
        self.signature = full_signature;
        self.public_key = public_key.serialize().to_vec();
        
        // Verify the signature we just created
        if !self.verify() {
            return Err("Failed to verify own signature".to_string());
        }
        
        Ok(())
    }
    
    /// Verify transaction signature with full cryptographic validation
    pub fn verify(&self) -> bool {
        // Coinbase transactions don't need signatures
        if self.is_coinbase() {
            return true;
        }
        
        // Must have signature and public key
        if self.signature.is_empty() || self.public_key.is_empty() {
            return false;
        }
        
        // Signature must be exactly 65 bytes
        if self.signature.len() != 65 {
            return false;
        }
        
        // Public key must be 33 bytes (compressed)
        if self.public_key.len() != 33 {
            return false;
        }
        
        let secp = Secp256k1::new();
        
        // Parse public key
        let public_key = match PublicKey::from_slice(&self.public_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        
        // Extract recovery ID and signature
        let recovery_id = match RecoveryId::from_i32(self.signature[64] as i32) {
            Ok(id) => id,
            Err(_) => return false,
        };
        
        let signature_bytes = &self.signature[..64];
        
        // Create recoverable signature
        let recoverable_sig = match RecoverableSignature::from_compact(signature_bytes, recovery_id) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        
        // Hash the signing data
        let signing_data = self.data_to_sign();
        let hash = double_sha256(&signing_data);
        let message = match Message::from_digest_slice(&hash) {
            Ok(msg) => msg,
            Err(_) => return false,
        };
        
        // Recover public key and verify it matches
        match secp.recover_ecdsa(&message, &recoverable_sig) {
            Ok(recovered_key) => {
                if recovered_key != public_key {
                    return false;
                }
                
                // Also verify with standard ECDSA
                let standard_sig = match Signature::from_compact(signature_bytes) {
                    Ok(sig) => sig,
                    Err(_) => return false,
                };
                
                secp.verify_ecdsa(&message, &standard_sig, &public_key).is_ok()
            }
            Err(_) => false,
        }
    }
    
    /// Calculate transaction hash
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(&self.version.to_be_bytes());
        hasher.update(&self.from);
        hasher.update(&self.to);
        hasher.update(&self.amount.to_be_bytes());
        hasher.update(&self.fee.to_be_bytes());
        hasher.update(&self.nonce.to_be_bytes());
        hasher.update(&self.chain_id.to_be_bytes());
        
        if self.expiry > 0 {
            hasher.update(&self.expiry.to_be_bytes());
        }
        
        if let Some(ref data) = self.data {
            hasher.update(data);
        }
        
        // Don't include signature in hash (allows signature malleability protection)
        
        // Double SHA-256
        let first_hash = hasher.finalize();
        let mut second_hasher = Sha256::new();
        second_hasher.update(first_hash);
        
        let result = second_hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Check if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.from == [0u8; 20]
    }
    
    /// Get transaction size in bytes
    pub fn size(&self) -> usize {
        bincode::serialize(self).map(|v| v.len()).unwrap_or(0)
    }
    
    /// Get total transaction cost (amount + fee)
    pub fn total_cost(&self) -> u64 {
        self.amount.saturating_add(self.fee)
    }
    
    /// Comprehensive transaction validation
    pub fn validate(&self, chain_id: Option<u64>) -> Result<(), String> {
        // Validate amounts
        if self.amount == 0 && !self.is_coinbase() {
            return Err("Transaction amount cannot be zero".to_string());
        }
        
        if self.amount > 21_000_000_000_000 { // Max supply check
            return Err("Transaction amount exceeds maximum supply".to_string());
        }
        
        // Validate fee
        if self.fee > self.amount / 2 && !self.is_coinbase() {
            return Err("Transaction fee too high (>50% of amount)".to_string());
        }
        
        // Validate addresses
        if self.from == self.to && !self.is_coinbase() {
            return Err("Cannot send to same address".to_string());
        }
        
        // Validate chain ID if provided
        if let Some(expected_chain_id) = chain_id {
            if self.chain_id != expected_chain_id {
                return Err("Invalid chain ID".to_string());
            }
        }
        
        // Check expiry
        if self.expiry > 0 {
            let now = Utc::now().timestamp() as u64;
            if now > self.expiry {
                return Err("Transaction has expired".to_string());
            }
        }
        
        // Verify signature
        if !self.verify() {
            return Err("Invalid signature".to_string());
        }
        
        // Validate data size if present
        if let Some(ref data) = self.data {
            if data.len() > 1024 { // Max 1KB data
                return Err("Transaction data too large".to_string());
            }
        }
        
        Ok(())
    }
}

/// Convert secp256k1 public key to 20-byte address (Bitcoin-compatible)
pub fn public_key_to_address(public_key: &PublicKey) -> Address {
    // Get compressed public key (33 bytes)
    let public_key_bytes = public_key.serialize();
    
    // Hash with SHA256, then RIPEMD160 (Bitcoin/Ethereum style)
    let sha_hash = double_sha256(&public_key_bytes);
    
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(&sha_hash);
    let ripemd_hash = ripemd_hasher.finalize();
    
    let mut address = [0u8; 20];
    address.copy_from_slice(&ripemd_hash);
    address
}

/// Bitcoin-style double SHA-256 hash
pub fn double_sha256(data: &[u8]) -> Hash {
    let first_hash = Sha256::digest(data);
    let second_hash = Sha256::digest(&first_hash);
    
    let mut result = [0u8; 32];
    result.copy_from_slice(&second_hash);
    result
}

/// Check if hash meets difficulty target (leading zero bits)
pub fn meets_difficulty_target(hash: &Hash, target_bits: u32) -> bool {
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
    
    count >= target_bits
}

/// Display implementations for better debugging
impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Block(height: {}, hash: {}, txs: {}, difficulty: {})",
            self.header.height,
            hex::encode(self.hash()),
            self.transactions.len(),
            self.header.difficulty_target
        )
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Transaction(from: {}, to: {}, amount: {}, fee: {}, nonce: {})",
            hex::encode(self.from),
            hex::encode(self.to),
            self.amount,
            self.fee,
            self.nonce
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::rand::rngs::OsRng;

    fn generate_keypair() -> (SecretKey, PublicKey, Address) {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        let address = public_key_to_address(&public_key);
        (secret_key, public_key, address)
    }

    #[test]
    fn test_transaction_creation_and_signing() {
        let (secret_key, public_key, address) = generate_keypair();
        let to_address = [1u8; 20];
        
        let mut tx = Transaction::new(
            address,
            to_address,
            1000000, // 1 PALI
            1000,    // 0.001 PALI fee
            1,
            1, // chain_id
        );
        
        assert!(tx.sign(&secret_key, &public_key).is_ok());
        assert!(tx.verify());
    }
    
    #[test]
    fn test_coinbase_transaction() {
        let address = [1u8; 20];
        let coinbase = Transaction::coinbase(address, 5000000, 1, 1);
        
        assert!(coinbase.is_coinbase());
        assert!(coinbase.verify());
        assert!(coinbase.validate(Some(1)).is_ok());
    }
    
    #[test]
    fn test_block_creation_and_validation() {
        let address = [1u8; 20];
        let coinbase = Transaction::coinbase(address, 5000000, 1, 1);
        let transactions = vec![coinbase];
        
        let block = Block::new([0; 32], transactions, 20, 1);
        
        assert!(block.verify_merkle_root());
        assert_eq!(block.header.tx_count, 1);
        assert!(block.coinbase_transaction().is_some());
    }
    
    #[test]
    fn test_proof_of_work() {
        let mut block = Block::new([0; 32], vec![], 1, 0); // Very easy difficulty
        
        // Mine the block
        while !block.is_valid_proof_of_work() {
            block.header.nonce += 1;
            if block.header.nonce > 1000000 {
                panic!("Could not mine block with reasonable effort");
            }
        }
        
        assert!(block.is_valid_proof_of_work());
    }
}
