// src/types.rs - Secure cryptographic types for Pali Coin
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use secp256k1::{
    Secp256k1, Message, SecretKey, PublicKey, 
    ecdsa::{Signature, RecoverableSignature, RecoveryId}
};
use ripemd::{Ripemd160, Digest as RipemdDigest};
use crate::error::{PaliError, Result};
use crate::utils::{hash, time, encoding, validation};
use std::fmt;

pub type Address = [u8; 20];
pub type Hash = [u8; 32];

/// Block header containing metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    /// Hash of the previous block
    pub prev_hash: Hash,
    
    /// Merkle root of all transactions in the block
    pub merkle_root: Hash,
    
    /// Block creation timestamp
    pub timestamp: u64,
    
    /// Block height in the chain
    pub height: u64,
    
    /// Proof-of-work nonce
    pub nonce: u64,
    
    /// Mining difficulty target
    pub difficulty: u32,
    
    /// Version for future upgrades
    pub version: u32,
    
    /// Number of transactions in block
    pub tx_count: u32,
}

impl Default for BlockHeader {
    fn default() -> Self {
        BlockHeader {
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: time::now(),
            height: 0,
            nonce: 0,
            difficulty: 20,
            version: 1,
            tx_count: 0,
        }
    }
}

/// Complete block with header, transactions, and optional ZK proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    
    /// All transactions in the block
    pub transactions: Vec<Transaction>,
    
    /// Optional zero-knowledge proof
    pub zk_proof: Option<Vec<u8>>,
    
    /// Block signature (for validator consensus)
    pub signature: Option<Vec<u8>>,
}

impl Block {
    /// Create a new block
    pub fn new(
        prev_hash: Hash,
        transactions: Vec<Transaction>,
        difficulty: u32,
        height: u64,
    ) -> Self {
        let tx_count = transactions.len() as u32;
        let merkle_root = hash::merkle_root(
            &transactions.iter().map(|tx| tx.hash()).collect::<Vec<_>>()
        );
        
        let header = BlockHeader {
            prev_hash,
            merkle_root,
            timestamp: time::now(),
            height,
            nonce: 0,
            difficulty,
            version: 1,
            tx_count,
        };
        
        Block {
            header,
            transactions,
            zk_proof: None,
            signature: None,
        }
    }
    
    /// Calculate block hash
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(&self.header.prev_hash);
        hasher.update(&self.header.merkle_root);
        hasher.update(&self.header.timestamp.to_be_bytes());
        hasher.update(&self.header.height.to_be_bytes());
        hasher.update(&self.header.nonce.to_be_bytes());
        hasher.update(&self.header.difficulty.to_be_bytes());
        hasher.update(&self.header.version.to_be_bytes());
        hasher.update(&self.header.tx_count.to_be_bytes());
        
        // Double SHA-256 for extra security (Bitcoin standard)
        let first_result = hasher.finalize();
        let mut second_hasher = Sha256::new();
        second_hasher.update(first_result);
        
        let result = second_hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Verify proof-of-work meets difficulty requirement
    pub fn is_valid_proof_of_work(&self) -> bool {
        let hash = self.hash();
        validation::meets_difficulty(&hash, self.header.difficulty)
    }
    
    /// Verify merkle root matches transactions
    pub fn verify_merkle_root(&self) -> bool {
        let calculated_root = hash::merkle_root(
            &self.transactions.iter().map(|tx| tx.hash()).collect::<Vec<_>>()
        );
        self.header.merkle_root == calculated_root
    }
    
    /// Get block size in bytes
    pub fn size(&self) -> usize {
        serde_json::to_vec(self).map(|v| v.len()).unwrap_or(0)
    }
    
    /// Check if block is genesis block
    pub fn is_genesis(&self) -> bool {
        self.header.height == 0 && self.header.prev_hash == [0; 32]
    }
    
    /// Get coinbase transaction (first transaction if it exists)
    pub fn coinbase_transaction(&self) -> Option<&Transaction> {
        self.transactions.first().filter(|tx| tx.is_coinbase())
    }
    
    /// Get non-coinbase transactions
    pub fn regular_transactions(&self) -> &[Transaction] {
        if self.transactions.is_empty() {
            &[]
        } else if self.transactions[0].is_coinbase() {
            &self.transactions[1..]
        } else {
            &self.transactions
        }
    }
    
    /// Comprehensive block validation
    pub fn validate(&self, prev_block: Option<&Block>) -> Result<()> {
        // Verify merkle root
        if !self.verify_merkle_root() {
            return Err(PaliError::BlockValidation("Invalid merkle root".to_string()));
        }
        
        // Verify proof of work
        if !self.is_valid_proof_of_work() {
            return Err(PaliError::ProofOfWork("Insufficient proof of work".to_string()));
        }
        
        // Verify timestamp
        if !time::is_valid_timestamp(self.header.timestamp, 7200) { // 2 hours max drift
            return Err(PaliError::BlockValidation("Invalid timestamp".to_string()));
        }
        
        // Verify block size
        if !validation::is_valid_block_size(self.size()) {
            return Err(PaliError::BlockValidation("Block too large".to_string()));
        }
        
        // Verify transaction count matches header
        if self.transactions.len() != self.header.tx_count as usize {
            return Err(PaliError::BlockValidation("Transaction count mismatch".to_string()));
        }
        
        // Verify against previous block if provided
        if let Some(prev) = prev_block {
            if self.header.prev_hash != prev.hash() {
                return Err(PaliError::BlockValidation("Invalid previous hash".to_string()));
            }
            
            if self.header.height != prev.header.height + 1 {
                return Err(PaliError::BlockValidation("Invalid block height".to_string()));
            }
            
            if self.header.timestamp <= prev.header.timestamp {
                return Err(PaliError::BlockValidation("Block timestamp not after previous".to_string()));
            }
        }
        
        // Validate all transactions
        for (i, tx) in self.transactions.iter().enumerate() {
            tx.validate(Some(1)).map_err(|e| {
                PaliError::BlockValidation(format!("Transaction {} invalid: {}", i, e))
            })?;
        }
        
        Ok(())
    }
}

/// Transaction with full cryptographic security
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    /// Sender address (20 bytes)
    pub from: Address,
    
    /// Recipient address (20 bytes)
    pub to: Address,
    
    /// Amount to transfer (in smallest units)
    pub amount: u64,
    
    /// Transaction fee
    pub fee: u64,
    
    /// Transaction nonce (prevents replay attacks)
    pub nonce: u64,
    
    /// Cryptographic signature (65 bytes: 64 + recovery_id)
    pub signature: Vec<u8>,
    
    /// Chain ID for replay protection
    pub chain_id: u64,
    
    /// Optional expiry timestamp (0 = no expiry)
    pub expiry: u64,
    
    /// Transaction version for future upgrades
    pub version: u32,
    
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
            from,
            to,
            amount,
            fee,
            nonce,
            signature: Vec::new(),
            chain_id,
            expiry: 0,
            version: 1,
            data: None,
        }
    }
    
    /// Create a coinbase transaction (mining reward)
    pub fn coinbase(to: Address, amount: u64, height: u64) -> Self {
        Transaction {
            from: [0u8; 20],
            to,
            amount,
            fee: 0,
            nonce: height, // Use height as nonce for coinbase
            signature: Vec::new(),
            chain_id: 1,
            expiry: 0,
            version: 1,
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
    
    /// Get data to be signed (everything except signature)
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.from);
        data.extend_from_slice(&self.to);
        data.extend_from_slice(&self.amount.to_be_bytes());
        data.extend_from_slice(&self.fee.to_be_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.chain_id.to_be_bytes());
        data.extend_from_slice(&self.version.to_be_bytes());
        
        if self.expiry > 0 {
            data.extend_from_slice(&self.expiry.to_be_bytes());
        }
        
        if let Some(ref tx_data) = self.data {
            data.extend_from_slice(tx_data);
        }
        
        data
    }
    
    /// Sign transaction with private key
    pub fn sign(&mut self, private_key: &SecretKey) -> Result<()> {
        let secp = Secp256k1::new();
        let signing_data = self.signing_data();
        
        // Hash the signing data
        let hash = hash::sha256(&signing_data);
        let message = Message::from_digest_slice(&hash)
            .map_err(|e| PaliError::Crypto(format!("Invalid message: {}", e)))?;
        
        // Create recoverable signature
        let signature = secp.sign_ecdsa_recoverable(&message, private_key);
        
        // Serialize with recovery ID
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let mut full_signature = Vec::with_capacity(65);
        full_signature.extend_from_slice(&signature_bytes);
        full_signature.push(recovery_id.to_i32() as u8);
        
        self.signature = full_signature;
        
        // Verify the signature we just created
        if !self.verify_signature()? {
            return Err(PaliError::Crypto("Failed to verify own signature".to_string()));
        }
        
        Ok(())
    }
    
    /// Verify transaction signature with full cryptographic validation
    pub fn verify_signature(&self) -> Result<bool> {
        // Coinbase transactions don't need signatures
        if self.is_coinbase() {
            return Ok(true);
        }
        
        // Must have signature
        if self.signature.is_empty() {
            return Ok(false);
        }
        
        // Signature must be exactly 65 bytes
        if self.signature.len() != 65 {
            return Ok(false);
        }
        
        let secp = Secp256k1::new();
        
        // Extract recovery ID and signature
        let recovery_id = RecoveryId::from_i32(self.signature[64] as i32)
            .map_err(|e| PaliError::Crypto(format!("Invalid recovery ID: {}", e)))?;
        
        let signature_bytes = &self.signature[..64];
        
        // Create recoverable signature
        let recoverable_sig = RecoverableSignature::from_compact(signature_bytes, recovery_id)
            .map_err(|e| PaliError::Crypto(format!("Invalid signature format: {}", e)))?;
        
        // Hash the signing data
        let signing_data = self.signing_data();
        let hash = hash::sha256(&signing_data);
        let message = Message::from_digest_slice(&hash)
            .map_err(|e| PaliError::Crypto(format!("Invalid message hash: {}", e)))?;
        
        // Recover public key
        let public_key = secp.recover_ecdsa(&message, &recoverable_sig)
            .map_err(|e| PaliError::Crypto(format!("Failed to recover public key: {}", e)))?;
        
        // Convert public key to address
        let recovered_address = public_key_to_address(&public_key);
        
        // Verify recovered address matches sender
        Ok(recovered_address == self.from)
    }
    
    /// Verify transaction with context (chain ID, expiry, etc.)
    pub fn verify_with_context(&self, expected_chain_id: u64) -> Result<bool> {
        // Verify chain ID for replay protection
        if self.chain_id != expected_chain_id {
            return Ok(false);
        }
        
        // Check expiry if set
        if self.expiry > 0 && time::now() > self.expiry {
            return Ok(false);
        }
        
        // Verify cryptographic signature
        self.verify_signature()
    }
    
    /// Calculate transaction hash
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(&self.from);
        hasher.update(&self.to);
        hasher.update(&self.amount.to_be_bytes());
        hasher.update(&self.fee.to_be_bytes());
        hasher.update(&self.nonce.to_be_bytes());
        hasher.update(&self.chain_id.to_be_bytes());
        hasher.update(&self.version.to_be_bytes());
        
        if self.expiry > 0 {
            hasher.update(&self.expiry.to_be_bytes());
        }
        
        if let Some(ref data) = self.data {
            hasher.update(data);
        }
        
        hasher.update(&self.signature);
        
        // Double SHA-256 for security
        let first_result = hasher.finalize();
        let mut second_hasher = Sha256::new();
        second_hasher.update(first_result);
        
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
        serde_json::to_vec(self).map(|v| v.len()).unwrap_or(0)
    }
    
    /// Get total transaction cost (amount + fee)
    pub fn total_cost(&self) -> u64 {
        self.amount.saturating_add(self.fee)
    }
    
    /// Comprehensive transaction validation
    pub fn validate(&self, chain_id: Option<u64>) -> Result<()> {
        // Validate amounts
        if !validation::is_valid_amount(self.amount) {
            return Err(PaliError::TransactionValidation("Invalid amount".to_string()));
        }
        
        if !validation::is_valid_fee(self.fee, self.amount) {
            return Err(PaliError::TransactionValidation("Invalid fee".to_string()));
        }
        
        // Validate addresses
        if self.from == self.to && !self.is_coinbase() {
            return Err(PaliError::TransactionValidation("Cannot send to same address".to_string()));
        }
        
        // Validate transaction size
        if self.size() > crate::constants::MAX_TRANSACTION_SIZE {
            return Err(PaliError::TransactionValidation("Transaction too large".to_string()));
        }
        
        // Validate chain ID if provided
        if let Some(expected_chain_id) = chain_id {
            if !self.verify_with_context(expected_chain_id)? {
                return Err(PaliError::TransactionValidation("Invalid signature or context".to_string()));
            }
        } else if !self.verify_signature()? {
            return Err(PaliError::TransactionValidation("Invalid signature".to_string()));
        }
        
        // Validate data size if present
        if let Some(ref data) = self.data {
            if data.len() > 1024 { // Max 1KB data
                return Err(PaliError::TransactionValidation("Transaction data too large".to_string()));
            }
        }
        
        Ok(())
    }
}

/// Convert secp256k1 public key to 20-byte address
pub fn public_key_to_address(public_key: &PublicKey) -> Address {
    // Get uncompressed public key (65 bytes: 0x04 + 32x + 32y)
    let public_key_bytes = public_key.serialize_uncompressed();
    
    // Hash with SHA256, then RIPEMD160 (Bitcoin/Ethereum style)
    let sha_hash = hash::sha256(&public_key_bytes[1..]); // Skip 0x04 prefix
    hash::hash160(&sha_hash)
}

/// Generate a key pair for testing
#[cfg(test)]
pub fn generate_keypair() -> (SecretKey, PublicKey, Address) {
    use rand::rngs::OsRng;
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
    let address = public_key_to_address(&public_key);
    (secret_key, public_key, address)
}

/// Display implementations for better debugging
impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Block(height: {}, hash: {}, txs: {})",
            self.header.height,
            encoding::to_hex(&self.hash()),
            self.transactions.len()
        )
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Transaction(from: {}, to: {}, amount: {}, fee: {})",
            encoding::to_hex(&self.from),
            encoding::to_hex(&self.to),
            self.amount,
            self.fee
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;

    #[test]
    fn test_transaction_creation_and_signing() {
        let (secret_key, _public_key, address) = generate_keypair();
        let to_address = [1u8; 20];
        
        let mut tx = Transaction::new(
            address,
            to_address,
            1000000, // 1 PALI
            1000,    // 0.001 PALI fee
            1,
            MAINNET_CHAIN_ID,
        );
        
        assert!(tx.sign(&secret_key).is_ok());
        assert!(tx.verify_signature().unwrap());
        assert!(tx.verify_with_context(MAINNET_CHAIN_ID).unwrap());
        assert!(!tx.verify_with_context(TESTNET_CHAIN_ID).unwrap());
    }
    
    #[test]
    fn test_coinbase_transaction() {
        let address = [1u8; 20];
        let coinbase = Transaction::coinbase(address, 5000000, 1);
        
        assert!(coinbase.is_coinbase());
        assert!(coinbase.verify_signature().unwrap());
        assert!(coinbase.validate(Some(MAINNET_CHAIN_ID)).is_ok());
    }
    
    #[test]
    fn test_block_creation_and_validation() {
        let address = [1u8; 20];
        let coinbase = Transaction::coinbase(address, 5000000, 1);
        let transactions = vec![coinbase];
        
        let block = Block::new([0; 32], transactions, 20, 1);
        
        assert!(block.verify_merkle_root());
        assert_eq!(block.header.tx_count, 1);
        assert!(block.coinbase_transaction().is_some());
    }
    
    #[test]
    fn test_proof_of_work() {
        let mut block = Block::new([0; 32], vec![], 1, 0); // Very easy difficulty
        
        // Mine the block (find valid nonce)
        while !block.is_valid_proof_of_work() {
            block.header.nonce += 1;
            if block.header.nonce > 1000000 {
                panic!("Could not mine block with reasonable effort");
            }
        }
        
        assert!(block.is_valid_proof_of_work());
    }
    
    #[test]
    fn test_invalid_signature() {
        let (_secret_key, _public_key, address) = generate_keypair();
        let to_address = [1u8; 20];
        
        let mut tx = Transaction::new(
            address,
            to_address,
            1000000,
            1000,
            1,
            MAINNET_CHAIN_ID,
        );
        
        // Set invalid signature
        tx.signature = vec![0u8; 65];
        
        assert!(!tx.verify_signature().unwrap());
    }
    
    #[test]
    fn test_transaction_validation() {
        let (secret_key, _public_key, address) = generate_keypair();
        let to_address = [1u8; 20];
        
        // Valid transaction
        let mut valid_tx = Transaction::new(address, to_address, 1000000, 1000, 1, MAINNET_CHAIN_ID);
        valid_tx.sign(&secret_key).unwrap();
        assert!(valid_tx.validate(Some(MAINNET_CHAIN_ID)).is_ok());
        
        // Invalid amount (0)
        let mut invalid_tx = Transaction::new(address, to_address, 0, 1000, 1, MAINNET_CHAIN_ID);
        invalid_tx.sign(&secret_key).unwrap();
        assert!(invalid_tx.validate(Some(MAINNET_CHAIN_ID)).is_err());
        
        // Self-send (non-coinbase)
        let mut self_send_tx = Transaction::new(address, address, 1000000, 1000, 1, MAINNET_CHAIN_ID);
        self_send_tx.sign(&secret_key).unwrap();
        assert!(self_send_tx.validate(Some(MAINNET_CHAIN_ID)).is_err());
    }
}
