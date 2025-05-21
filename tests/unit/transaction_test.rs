// tests/unit/transaction_test.rs
use pali_coin::types::Transaction;
use pali_coin::wallet::Wallet;
use std::error::Error;
use bincode;
use std::collections::HashSet;

#[test]
fn test_transaction_creation_and_verification() {
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    let chain_id = 1;
    
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        100,  // amount
        1,    // fee
        0,    // nonce
        chain_id
    );
    
    wallet.sign_transaction(&mut tx).expect("Failed to sign transaction");
    
    // Transaction should be valid
    assert!(tx.verify(), "Transaction verification failed");
    
    // Modify transaction data - verification should fail
    let mut modified_tx = tx.clone();
    modified_tx.amount = 200;
    modified_tx.signature = tx.signature.clone();
    assert!(!modified_tx.verify(), "Modified transaction should fail verification");
}

#[test]
fn test_replay_protection() {
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    
    // Create transactions with different chain IDs
    let mut tx1 = Transaction::new(wallet.address, recipient, 100, 1, 0, 1);
    let mut tx2 = Transaction::new(wallet.address, recipient, 100, 1, 0, 2);
    
    wallet.sign_transaction(&mut tx1).expect("Failed to sign tx1");
    wallet.sign_transaction(&mut tx2).expect("Failed to sign tx2");
    
    // Signatures should be different
    assert_ne!(tx1.signature, tx2.signature, "Signatures should be different for different chain IDs");
    
    // Hashes should be different
    assert_ne!(tx1.hash(), tx2.hash(), "Hashes should be different for different chain IDs");
}

#[test]
fn test_transaction_serialization() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    let chain_id = 1;
    
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        100,
        1,
        0,
        chain_id
    );
    
    wallet.sign_transaction(&mut tx)?;
    
    // Serialize the transaction
    let serialized = bincode::serialize(&tx)?;
    
    // Deserialize
    let deserialized: Transaction = bincode::deserialize(&serialized)?;
    
    // Ensure all fields match
    assert_eq!(tx.from, deserialized.from, "From addresses should match");
    assert_eq!(tx.to, deserialized.to, "To addresses should match");
    assert_eq!(tx.amount, deserialized.amount, "Amounts should match");
    assert_eq!(tx.fee, deserialized.fee, "Fees should match");
    assert_eq!(tx.nonce, deserialized.nonce, "Nonces should match");
    assert_eq!(tx.chain_id, deserialized.chain_id, "Chain IDs should match");
    assert_eq!(tx.signature, deserialized.signature, "Signatures should match");
    assert_eq!(tx.public_key, deserialized.public_key, "Public keys should match");
    
    // The deserialized transaction should still verify
    assert!(deserialized.verify(), "Deserialized transaction should verify");
    
    Ok(())
}

#[test]
fn test_transaction_hash() {
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    let chain_id = 1;
    
    // Create a transaction
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        100,
        1,
        0,
        chain_id
    );
    
    // Get the hash before signing
    let hash_before = tx.hash();
    
    // Sign the transaction
    wallet.sign_transaction(&mut tx).expect("Failed to sign transaction");
    
    // Get the hash after signing
    let hash_after = tx.hash();
    
    // Hashes should be the same, as the signature isn't included in the hash calculation
    assert_eq!(hash_before, hash_after, "Hash should not change after signing");
    
    // Create an identical transaction
    let mut tx2 = Transaction::new(
        wallet.address,
        recipient,
        100,
        1,
        0,
        chain_id
    );
    
    // Hashes should be the same for identical transactions
    assert_eq!(tx.hash(), tx2.hash(), "Identical transactions should have the same hash");
    
    // Modify the transaction
    tx2.amount = 200;
    
    // Hashes should be different now
    assert_ne!(tx.hash(), tx2.hash(), "Different transactions should have different hashes");
}

#[test]
fn test_transaction_hash_uniqueness() {
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    let chain_id = 1;
    
    let mut hashes = HashSet::new();
    
    // Create transactions with different parameters
    for amount in [100, 200, 300] {
        for fee in [1, 2, 3] {
            for nonce in [0, 1, 2] {
                let tx = Transaction::new(
                    wallet.address,
                    recipient,
                    amount,
                    fee,
                    nonce,
                    chain_id
                );
                
                let hash = tx.hash();
                assert!(hashes.insert(hash), "Transaction hash should be unique");
            }
        }
    }
    
    // Should have 27 unique hashes (3 amounts * 3 fees * 3 nonces)
    assert_eq!(hashes.len(), 27, "Should have 27 unique hashes");
}

#[test]
fn test_transaction_data_signing() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    let chain_id = 1;
    
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        100,
        1,
        0,
        chain_id
    );
    
    // Sign the transaction
    wallet.sign_transaction(&mut tx)?;
    
    // Get the data that was signed
    let data_to_sign = tx.data_to_sign();
    
    // Manually verify the signature using the wallet
    let signature_is_valid = wallet.verify_signature(&data_to_sign, &tx.signature);
    assert!(signature_is_valid, "Manually verifying transaction signature failed");
    
    Ok(())
}

#[test]
fn test_different_transactions_same_wallet() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wallet = Wallet::new();
    let recipient1 = [1u8; 20];
    let recipient2 = [2u8; 20];
    let chain_id = 1;
    
    // Create two different transactions
    let mut tx1 = Transaction::new(
        wallet.address,
        recipient1,
        100,
        1,
        0,
        chain_id
    );
    
    let mut tx2 = Transaction::new(
        wallet.address,
        recipient2,
        200,
        2,
        1,
        chain_id
    );
    
    // Sign both transactions
    wallet.sign_transaction(&mut tx1)?;
    wallet.sign_transaction(&mut tx2)?;
    
    // Both should verify
    assert!(tx1.verify(), "Transaction 1 failed to verify");
    assert!(tx2.verify(), "Transaction 2 failed to verify");
    
    // But should have different signatures
    assert_ne!(tx1.signature, tx2.signature, "Different transactions should have different signatures");
    
    // And different hashes
    assert_ne!(tx1.hash(), tx2.hash(), "Different transactions should have different hashes");
    
    Ok(())
}

#[test]
fn test_transaction_with_zero_fees() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    let chain_id = 1;
    
    // Create a transaction with zero fee
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        100,
        0,  // zero fee
        0,
        chain_id
    );
    
    // Sign and verify
    wallet.sign_transaction(&mut tx)?;
    assert!(tx.verify(), "Transaction with zero fee failed to verify");
    
    Ok(())
}

#[test]
fn test_transaction_fees_calculation() {
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    let chain_id = 1;
    
    // Create transactions with different fees
    let tx1 = Transaction::new(wallet.address, recipient, 100, 1, 0, chain_id);
    let tx2 = Transaction::new(wallet.address, recipient, 100, 2, 0, chain_id);
    let tx3 = Transaction::new(wallet.address, recipient, 100, 5, 0, chain_id);
    
    // Check fee calculation (this is just a basic example, adjust based on your actual fee calculation method)
    assert_eq!(tx1.fee, 1, "Fee calculation incorrect for tx1");
    assert_eq!(tx2.fee, 2, "Fee calculation incorrect for tx2");
    assert_eq!(tx3.fee, 5, "Fee calculation incorrect for tx3");
    
    // Calculate total amounts (amount + fee)
    assert_eq!(tx1.amount + tx1.fee, 101, "Total calculation incorrect for tx1");
    assert_eq!(tx2.amount + tx2.fee, 102, "Total calculation incorrect for tx2");
    assert_eq!(tx3.amount + tx3.fee, 105, "Total calculation incorrect for tx3");
}

#[test]
fn test_transaction_to_self() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wallet = Wallet::new();
    let chain_id = 1;
    
    // Create a transaction where sender = recipient
    let mut tx = Transaction::new(
        wallet.address,
        wallet.address,  // sending to self
        100,
        1,
        0,
        chain_id
    );
    
    // Sign and verify
    wallet.sign_transaction(&mut tx)?;
    assert!(tx.verify(), "Transaction to self failed to verify");
    
    Ok(())
}

#[test]
fn test_transaction_with_large_values() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    let chain_id = 1;
    
    // Create a transaction with large values
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        u64::MAX / 2,  // large amount
        u64::MAX / 4,  // large fee
        u64::MAX / 8,  // large nonce
        chain_id
    );
    
    // Sign and verify
    wallet.sign_transaction(&mut tx)?;
    assert!(tx.verify(), "Transaction with large values failed to verify");
    
    Ok(())
}

#[test]
fn test_multiple_transactions_same_nonce() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wallet = Wallet::new();
    let recipient1 = [1u8; 20];
    let recipient2 = [2u8; 20];
    let chain_id = 1;
    
    // Create two transactions with the same nonce but different recipients
    let mut tx1 = Transaction::new(
        wallet.address,
        recipient1,
        100,
        1,
        0,  // same nonce
        chain_id
    );
    
    let mut tx2 = Transaction::new(
        wallet.address,
        recipient2,
        200,
        2,
        0,  // same nonce
        chain_id
    );
    
    // Sign both transactions
    wallet.sign_transaction(&mut tx1)?;
    wallet.sign_transaction(&mut tx2)?;
    
    // Both should verify independently
    assert!(tx1.verify(), "Transaction 1 failed to verify");
    assert!(tx2.verify(), "Transaction 2 failed to verify");
    
    // But they should have different hashes
    assert_ne!(tx1.hash(), tx2.hash(), "Transactions with same nonce should have different hashes if other fields differ");
    
    Ok(())
}
