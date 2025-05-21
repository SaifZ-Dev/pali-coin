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
}

impl Transaction {
    pub fn new(from: Address, to: Address, amount: u64, fee: u64, nonce: u64) -> Self {
        Transaction {
            from,
            to,
            amount,
            fee,
            nonce,
            signature: Vec::new(),
        }
    }
    
    // Data to be signed - returns all transaction data excluding the signature
    pub fn data_to_sign(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.from);
        data.extend_from_slice(&self.to);
        data.extend_from_slice(&self.amount.to_be_bytes());
        data.extend_from_slice(&self.fee.to_be_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());
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
        
        // Return true for coinbase transactions, false for others
        // This will be improved in future versions
        self.from == [0u8; 20]
    }
    
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(&self.from);
        hasher.update(&self.to);
        hasher.update(&self.amount.to_be_bytes());
        hasher.update(&self.fee.to_be_bytes());
        hasher.update(&self.nonce.to_be_bytes());
        hasher.update(&self.signature);
        
        let result = hasher.finalize();
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
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    pub fn is_valid_proof_of_work(&self) -> bool {
        let hash = self.hash();
        Self::meets_difficulty(&hash, self.header.difficulty as usize)
    }
    
    fn meets_difficulty(hash: &[u8; 32], difficulty: usize) -> bool {
        // Check if the first 'difficulty' bits are zero
        for i in 0..difficulty / 8 {
            if hash[i] != 0 {
                return false;
            }
        }
        
        // Check remaining bits
        if difficulty % 8 != 0 {
            let mask = 0xFF << (8 - (difficulty % 8));
            if hash[difficulty / 8] & mask != 0 {
                return false;
            }
        }
        
        true
    }
}
