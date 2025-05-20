use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Hash = [u8; 32];
pub type Address = [u8; 20];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub zk_proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub prev_hash: Hash,
    pub merkle_root: Hash,
    pub timestamp: u64,
    pub nonce: u64,
    pub difficulty: u32,
    pub height: u64,
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

impl Block {
    pub fn new(prev_hash: Hash, transactions: Vec<Transaction>, height: u64) -> Self {
        let merkle_root = Self::calculate_merkle_root(&transactions);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Block {
            header: BlockHeader {
                prev_hash,
                merkle_root,
                timestamp,
                nonce: 0,
                difficulty: 16,
                height,
            },
            transactions,
            zk_proof: None,
        }
    }

    pub fn hash(&self) -> Hash {
        let serialized = bincode::serialize(&self.header).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(serialized);
        hasher.finalize().into()
    }

    fn calculate_merkle_root(transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return [0; 32];
        }

        let mut hashes: Vec<Hash> = transactions
            .iter()
            .map(|tx| {
                let serialized = bincode::serialize(tx).unwrap();
                let mut hasher = Sha256::new();
                hasher.update(serialized);
                hasher.finalize().into()
            })
            .collect();

        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(chunk[1]);
                } else {
                    hasher.update(chunk[0]);
                }
                next_level.push(hasher.finalize().into());
            }
            hashes = next_level;
        }

        hashes[0]
    }

    pub fn is_valid_proof_of_work(&self) -> bool {
        let hash = self.hash();
        let difficulty_bytes = (self.header.difficulty / 8) as usize;
        let difficulty_bits = self.header.difficulty % 8;

        for i in 0..difficulty_bytes {
            if hash[i] != 0 {
                return false;
            }
        }

        if difficulty_bits > 0 && difficulty_bytes < hash.len() {
            let mask = 0xFF << (8 - difficulty_bits);
            if hash[difficulty_bytes] & mask != 0 {
                return false;
            }
        }

        true
    }
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

    pub fn hash(&self) -> Hash {
        let mut tx_for_hash = self.clone();
        tx_for_hash.signature = Vec::new();

        let serialized = bincode::serialize(&tx_for_hash).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(serialized);
        hasher.finalize().into()
    }
}
