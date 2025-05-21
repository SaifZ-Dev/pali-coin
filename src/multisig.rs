use crate::wallet::Wallet;
use crate::types::{Transaction, Address};
use secp256k1::{Secp256k1, Message, PublicKey};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::error::Error;

// M-of-N multisignature wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigWallet {
    pub threshold: usize,            // M in M-of-N
    pub public_keys: Vec<Vec<u8>>,   // N public keys
    pub address: Address,            // Generated address for the multisig wallet
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartiallySignedTransaction {
    pub transaction: Transaction,
    pub signatures: Vec<Option<Vec<u8>>>, // Vector of optional signatures, indexed by signer
}

impl MultisigWallet {
    // Create a new M-of-N multisignature wallet
    pub fn new(threshold: usize, public_keys: Vec<Vec<u8>>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        if threshold == 0 || threshold > public_keys.len() {
            return Err(format!("Invalid threshold: {} of {}", threshold, public_keys.len()).into());
        }
        
        if public_keys.is_empty() || public_keys.len() > 15 {
            return Err("Number of signers must be between 1 and 15".into());
        }
        
        // Generate the multisig address from all public keys
        let address = Self::generate_multisig_address(&public_keys, threshold)?;
        
        Ok(MultisigWallet {
            threshold,
            public_keys,
            address,
        })
    }
    
    // Generate a deterministic address from the public keys and threshold
    fn generate_multisig_address(public_keys: &[Vec<u8>], threshold: usize) -> Result<Address, Box<dyn Error + Send + Sync>> {
        // Sort public keys for deterministic address generation
        let mut sorted_keys = public_keys.to_vec();
        sorted_keys.sort();
        
        // Create a hash of threshold and all public keys
        let mut hasher = Sha256::new();
        
        // Add the threshold
        hasher.update(&[threshold as u8]);
        
        // Add the number of public keys
        hasher.update(&[public_keys.len() as u8]);
        
        // Add each public key
        for key in &sorted_keys {
            hasher.update(key);
        }
        
        let sha256_hash = hasher.finalize();
        
        // Apply RIPEMD160 to the SHA256 hash (same as regular address generation)
        let mut ripemd_hasher = ripemd::Ripemd160::new();
        ripemd_hasher.update(&sha256_hash);
        let ripemd_hash = ripemd_hasher.finalize();
        
        // Create the address
        let mut address = [0u8; 20];
        address.copy_from_slice(&ripemd_hash);
        
        Ok(address)
    }
    
    // Create a new partially signed transaction
    pub fn create_transaction(&self, to: Address, amount: u64, fee: u64, nonce: u64, chain_id: u64, version: u8) -> PartiallySignedTransaction {
        // Create a transaction from the multisig address
        let tx = Transaction {
            version,
            from: self.address,
            to,
            amount,
            fee,
            nonce,
            chain_id,
            public_key: Vec::new(), // We'll populate this differently for multisig
            signature: Vec::new(),  // We'll populate this from collected signatures
        };
        
        // Initialize with empty signatures
        let signatures = vec![None; self.public_keys.len()];
        
        PartiallySignedTransaction {
            transaction: tx,
            signatures,
        }
    }
    
    // Add a signature from one of the wallet participants
    pub fn add_signature(&self, tx: &mut PartiallySignedTransaction, wallet: &Wallet, signer_index: usize) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Check if the signer index is valid
        if signer_index >= self.public_keys.len() {
            return Err(format!("Invalid signer index: {}", signer_index).into());
        }
        
        // Check if this wallet's public key matches the expected one
        if wallet.public_key.to_vec() != self.public_keys[signer_index] {
            return Err("Wallet public key does not match the registered key for this signer".into());
        }
        
        // Get the data to sign
        let data = tx.transaction.data_to_sign();
        
        // Sign the data
        let signature = wallet.sign_data(&data);
        
        // Add the signature
        tx.signatures[signer_index] = Some(signature);
        
        Ok(())
    }
    
    // Finalize the transaction if enough signatures are collected
    pub fn finalize_transaction(&self, tx: &mut PartiallySignedTransaction) -> Result<Transaction, Box<dyn Error + Send + Sync>> {
        // Count valid signatures
        let valid_signatures = tx.signatures.iter()
            .filter(|s| s.is_some())
            .count();
        
        // Check if we have enough signatures
        if valid_signatures < self.threshold {
            return Err(format!("Not enough signatures: {} of {} required", 
                             valid_signatures, self.threshold).into());
        }
        
        // Combine the signatures and public keys into a special format:
        // Format: [threshold][sig_count][sig1_len][sig1]...[sigN_len][sigN][pub_count][pub1_len][pub1]...[pubN_len][pubN]
        let mut combined_data = Vec::new();
        
        // Add threshold
        combined_data.push(self.threshold as u8);
        
        // Add signature count
        let mut sig_count = 0;
        let mut signatures = Vec::new();
        
        for (i, sig_opt) in tx.signatures.iter().enumerate() {
            if let Some(sig) = sig_opt {
                sig_count += 1;
                signatures.push((i, sig.clone()));
            }
        }
        combined_data.push(sig_count as u8);
        
        // Add signatures
        for (i, sig) in signatures {
            combined_data.push(sig.len() as u8);
            combined_data.extend_from_slice(&sig);
            combined_data.push(i as u8); // Add signer index for verification
        }
        
        // Add public key count
        combined_data.push(self.public_keys.len() as u8);
        
        // Add public keys
        for key in &self.public_keys {
            combined_data.push(key.len() as u8);
            combined_data.extend_from_slice(key);
        }
        
        // Create the final transaction
        let mut final_tx = tx.transaction.clone();
        final_tx.public_key = combined_data;
        
        // For multisig, the "signature" field is actually a special marker
        final_tx.signature = vec![0xFF, 0xFE, 0xFD, 0xFC]; // Special marker for multisig
        
        Ok(final_tx)
    }
    
    // Verify a multisig transaction
    pub fn verify_transaction(tx: &Transaction) -> bool {
        // Check if this is a multisig transaction
        if tx.signature != vec![0xFF, 0xFE, 0xFD, 0xFC] {
            return false;
        }
        
        // The public_key field contains our combined data
        let public_key_data = &tx.public_key;
        
        // Parse the combined data
        if public_key_data.len() < 2 {
            return false;
        }
        
        let threshold = public_key_data[0] as usize;
        let sig_count = public_key_data[1] as usize;
        
        if sig_count < threshold {
            return false;
        }
        
        let mut index = 2;
        let mut valid_signatures = 0;
        let secp = Secp256k1::new();
        
        // Data to verify
        let data_to_sign = tx.data_to_sign();
        let mut hasher = Sha256::new();
        hasher.update(&data_to_sign);
        let hash = hasher.finalize();
        
        let message = match Message::from_digest_slice(&hash) {
            Ok(msg) => msg,
            Err(_) => return false,
        };
        
        // Verify each signature
        for _ in 0..sig_count {
            if index >= public_key_data.len() {
                return false;
            }
            
            let sig_len = public_key_data[index] as usize;
            index += 1;
            
            if index + sig_len >= public_key_data.len() {
                return false;
            }
            
            let signature = &public_key_data[index..index + sig_len];
            index += sig_len;
            
            if index >= public_key_data.len() {
                return false;
            }
            
            let signer_index = public_key_data[index] as usize;
            index += 1;
            
            // Skip parsing the public keys if we don't have enough data
            if index >= public_key_data.len() {
                return false;
            }
            
            let pub_count = public_key_data[index] as usize;
            index += 1;
            
            // Parse public keys and find the one for this signer
            let mut pub_key_found = false;
            let mut public_key = None;
            
            for i in 0..pub_count {
                if index >= public_key_data.len() {
                    return false;
                }
                
                let key_len = public_key_data[index] as usize;
                index += 1;
                
                if index + key_len > public_key_data.len() {
                    return false;
                }
                
                if i == signer_index {
                    let key_data = &public_key_data[index..index + key_len];
                    public_key = Some(key_data);
                    pub_key_found = true;
                }
                
                index += key_len;
            }
            
            if !pub_key_found || public_key.is_none() {
                return false;
            }
            
            // Verify this signature
            if signature.len() != 64 {
                return false;
            }
            
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(signature);
            
            let signature = match secp256k1::ecdsa::Signature::from_compact(&sig_bytes) {
                Ok(sig) => sig,
                Err(_) => return false,
            };
            
            let pub_key_bytes = public_key.unwrap();
            let public_key = match PublicKey::from_slice(pub_key_bytes) {
                Ok(key) => key,
                Err(_) => return false,
            };
            
            if secp.verify_ecdsa(&message, &signature, &public_key).is_ok() {
                valid_signatures += 1;
            }
        }
        
        valid_signatures >= threshold
    }
}
