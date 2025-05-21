use serde::{Serialize, Deserialize};
use crate::wallet::Wallet;
use sha2::{Sha256, Digest};
use std::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HDWallet {
    seed: Vec<u8>,
    mnemonic: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HDAccount {
    pub account_index: u32,
    pub external_addresses: Vec<Wallet>, // Receiving addresses
    pub internal_addresses: Vec<Wallet>, // Change addresses
}

impl HDWallet {
    // Create a new HD wallet from a seed
    pub fn new_from_seed(seed: &[u8]) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(HDWallet {
            seed: seed.to_vec(),
            mnemonic: None,
        })
    }
    
    // Create a new HD wallet from a mnemonic phrase
    pub fn new_from_mnemonic(mnemonic: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mnemonic_obj = bip39::Mnemonic::parse_in(bip39::Language::English, mnemonic)
            .map_err(|e| format!("Invalid mnemonic: {}", e))?;
        
        let seed = mnemonic_obj.to_seed("");
        
        Ok(HDWallet {
            seed: seed.to_vec(),
            mnemonic: Some(mnemonic.to_string()),
        })
    }
    
    // Derive an account using a simplified approach
    pub fn derive_account(&self, account_index: u32) -> Result<HDAccount, Box<dyn Error + Send + Sync>> {
        let mut external_addresses = Vec::new();
        let mut internal_addresses = Vec::new();
        
        // Simplified derivation - we'll derive keys based on seed + index
        for i in 0..10u32 {
            // External addresses - derive using account_index and address index
            let mut hasher = Sha256::new();
            hasher.update(&self.seed);
            hasher.update(&account_index.to_be_bytes());
            hasher.update(&0u32.to_be_bytes()); // external chain
            hasher.update(&i.to_be_bytes());
            let hash = hasher.finalize();
            
            let mut private_key = [0u8; 32];
            private_key.copy_from_slice(&hash);
            
            let wallet = Wallet::from_private_key(&private_key);
            external_addresses.push(wallet);
            
            // Internal addresses - same but with different chain code
            let mut hasher = Sha256::new();
            hasher.update(&self.seed);
            hasher.update(&account_index.to_be_bytes());
            hasher.update(&1u32.to_be_bytes()); // internal chain
            hasher.update(&i.to_be_bytes());
            let hash = hasher.finalize();
            
            let mut private_key = [0u8; 32];
            private_key.copy_from_slice(&hash);
            
            let wallet = Wallet::from_private_key(&private_key);
            internal_addresses.push(wallet);
        }
        
        Ok(HDAccount {
            account_index,
            external_addresses,
            internal_addresses,
        })
    }
    
    // Get the mnemonic if available
    pub fn get_mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }
}
