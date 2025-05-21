use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

pub type Address = [u8; 20];
pub type Hash = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub prev_hash: Hash,
    pub merkle_root: Hash,
    pub timestamp: u64,
    pub height: u64,
    pub nonce: u64,
    pub difficulty: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub zk_proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub from: Address,
    pub to: Address,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub signature: Vec<u8>,
    pub chain_id: u64,      // Chain ID for replay protection
    pub expiry: u64,        // Optional expiry timestamp (0 = no expiry)
}

impl Transaction {
    pub fn new(from: Address, to: Address, amount: u64, fee: u64, nonce: u64, chain_id: u64) -> Self {
        Transaction {
            from,
            to,
            amount,
            fee,
            nonce,
            signature: Vec::new(),
            chain_id,
            expiry: 0,       // Default: no expiry
        }
    }
    
    // Set an expiry time for the transaction
    pub fn with_expiry(mut self, expiry_timestamp: u64) -> Self {
        self.expiry = expiry_timestamp;
        self
    }
    
    // Data to be signed - returns all transaction data excluding the signature
    pub fn data_to_sign(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.from);
        data.extend_from_slice(&self.to);
        data.extend_from_slice(&self.amount.to_be_bytes());
        data.extend_from_slice(&self.fee.to_be_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.chain_id.to_be_bytes()); // Include chain_id in signed data
        
        if self.expiry > 0 {
            data.extend_from_slice(&self.expiry.to_be_bytes()); // Include expiry if set
        }
        
        data
    }
    
    // Verify the transaction signature
    pub fn verify(&self) -> bool {
        // Coinbase transactions (mining rewards) don't need signatures
        if self.from == [0u8; 20] {
            return true;
        }
        
        // If signature is empty, transaction is invalid
        if self.signature.is_empty() {
            return false;
        }
        
        // NOTE: In a real implementation, you would extract the public key
        // from the transaction data and verify the signature.
        // For now, we're using a simplified approach where verification
        // is handled elsewhere.
        
        // This is just a placeholder for now
        true
    }
    
    // Verify with replay protection by including chain ID context
    pub fn verify_with_context(&self, expected_chain_id: u64) -> bool {
        // First verify chain ID matches to prevent replay attacks across chains
        if self.chain_id != expected_chain_id {
            return false;
        }
        
        // Then do regular verification
        self.verify()
    }
    
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(&self.from);
        hasher.update(&self.to);
        hasher.update(&self.amount.to_be_bytes());
        hasher.update(&self.fee.to_be_bytes());
        hasher.update(&self.nonce.to_be_bytes());
        hasher.update(&self.chain_id.to_be_bytes());
        
        if self.expiry > 0 {
            hasher.update(&self.expiry.to_be_bytes());
        }
        
        hasher.update(&self.signature);
        
        // Double SHA-256 for extra security (like Bitcoin)
        let first_result = hasher.finalize();
        let mut second_hasher = Sha256::new();
        second_hasher.update(first_result);
        
        let result = second_hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

impl Block {
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(&self.header.prev_hash);
        hasher.update(&self.header.merkle_root);
        hasher.update(&self.header.timestamp.to_be_bytes());
        hasher.update(&self.header.height.to_be_bytes());
        hasher.update(&self.header.nonce.to_be_bytes());
        hasher.update(&self.header.difficulty.to_be_bytes());
        
        // Double SHA-256 for extra security (like Bitcoin)
        let first_result = hasher.finalize();
        let mut second_hasher = Sha256::new();
        second_hasher.update(first_result);
        
        let result = second_hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    pub fn is_valid_proof_of_work(&self) -> bool {
        let hash = self.hash();
        Self::meets_difficulty(&hash, self.header.difficulty as usize)
    }
    
    fn meets_difficulty(hash: &[u8; 32], difficulty: usize) -> bool {
        // Enhanced difficulty check - count leading zero bits
        let mut count = 0;
        
        for byte in hash {
            let mut byte_value = *byte;
            if byte_value == 0 {
                count += 8;
                continue;
            }
            
            // Count leading zero bits in this byte
            while byte_value & 0x80 == 0 {
                count += 1;
                byte_value <<= 1;
            }
            break;
        }
        
        // Check if we have enough leading zeros
        count >= difficulty
    }
}
