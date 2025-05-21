// tests/unit/wallet_test.rs
use pali_coin::wallet::Wallet;
use pali_coin::types::Transaction;
use std::error::Error;
use std::fs;
use std::path::Path;
use rand::rngs::OsRng;

fn setup() {
    // Clean up any existing test data
    let path = Path::new("wallet_test_data");
    if path.exists() {
        fs::remove_dir_all(path).expect("Failed to clean test directory");
    }
    fs::create_dir_all(path).expect("Failed to create test directory");
}

#[test]
fn test_wallet_creation() {
    let wallet = Wallet::new();
    assert_eq!(wallet.public_key.len(), 33, "Public key should be 33 bytes (compressed)");
    assert_eq!(wallet.address.len(), 20, "Address should be 20 bytes (RIPEMD160 of SHA256)");
}

#[test]
fn test_wallet_from_private_key() {
    // Create a wallet with a random private key
    let wallet1 = Wallet::new();
    
    // Create a second wallet from the first wallet's private key
    let wallet2 = Wallet::from_private_key(&wallet1.get_private_key());
    
    // Both wallets should have the same address and public key
    assert_eq!(wallet1.address, wallet2.address, "Addresses should match");
    assert_eq!(wallet1.public_key, wallet2.public_key, "Public keys should match");
}

#[test]
fn test_signature_validation() {
    let wallet = Wallet::new();
    let data = b"test message";
    let signature = wallet.sign_data(data);
    
    // Valid signature and data
    assert!(wallet.verify_signature(data, &signature), "Signature verification failed for valid data");
    
    // Invalid data
    let invalid_data = b"wrong message";
    assert!(!wallet.verify_signature(invalid_data, &signature), "Signature validation succeeded for invalid data");
}

#[test]
fn test_seed_phrase_recovery() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (wallet, seed_phrase) = Wallet::new_with_seed_phrase();
    
    // Make sure the seed phrase is non-empty
    assert!(!seed_phrase.is_empty(), "Seed phrase should not be empty");
    
    // Recover wallet from seed phrase
    let recovered_wallet = Wallet::from_seed_phrase(&seed_phrase)?;
    
    // Both wallets should have the same address and public key
    assert_eq!(wallet.address, recovered_wallet.address, "Addresses should match");
    assert_eq!(wallet.public_key, recovered_wallet.public_key, "Public keys should match");
    
    Ok(())
}

#[test]
fn test_transaction_signing() -> Result<(), Box<dyn Error + Send + Sync>> {
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
    
    // Sign the transaction
    wallet.sign_transaction(&mut tx)?;
    
    // The transaction should now have a valid signature
    assert!(!tx.signature.is_empty(), "Transaction signature should not be empty");
    assert!(tx.verify(), "Transaction signature verification failed");
    
    // Modify the transaction data - verification should fail
    let mut modified_tx = tx.clone();
    modified_tx.amount = 200;
    assert!(!modified_tx.verify(), "Modified transaction verification succeeded");
    
    Ok(())
}

#[test]
fn test_wallet_save_and_load() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new wallet
    let wallet = Wallet::new();
    let password = "test_password123";
    let filepath = "wallet_test_data/wallet.json";
    
    // Save the wallet
    wallet.save(filepath, password)?;
    
    // Verify the file exists
    assert!(Path::new(filepath).exists(), "Wallet file was not created");
    
    // Load the wallet
    let loaded_wallet = Wallet::load(filepath, password)?;
    
    // Verify the loaded wallet has the same address and public key
    assert_eq!(wallet.address, loaded_wallet.address, "Addresses should match");
    assert_eq!(wallet.public_key, loaded_wallet.public_key, "Public keys should match");
    
    // Try loading with wrong password - should fail
    let wrong_password = "wrong_password";
    let load_result = Wallet::load(filepath, wrong_password);
    assert!(load_result.is_err(), "Loading with wrong password should fail");
    
    Ok(())
}

#[test]
fn test_wallet_with_seed_phrase_save_and_load() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new wallet with seed phrase
    let (wallet, seed_phrase) = Wallet::new_with_seed_phrase();
    let password = "test_password123";
    let filepath = "wallet_test_data/wallet_with_seed.json";
    
    // Save the wallet with seed phrase
    wallet.save_with_seed_phrase(filepath, password, &seed_phrase)?;
    
    // Load the wallet with seed phrase
    let (loaded_wallet, loaded_seed_phrase) = Wallet::load_with_seed_phrase(filepath, password)?;
    
    // Verify the loaded wallet and seed phrase match
    assert_eq!(wallet.address, loaded_wallet.address, "Addresses should match");
    assert_eq!(wallet.public_key, loaded_wallet.public_key, "Public keys should match");
    assert_eq!(seed_phrase, loaded_seed_phrase, "Seed phrases should match");
    
    Ok(())
}

#[test]
fn test_wallet_address_format() {
    let wallet = Wallet::new();
    
    // Get hexadecimal representation of the address
    let address_hex = hex::encode(wallet.address);
    
    // Address should be 40 characters in hex (20 bytes)
    assert_eq!(address_hex.len(), 40, "Hex address should be 40 characters");
    
    // Verify the address is valid hexadecimal
    assert!(address_hex.chars().all(|c| c.is_digit(16)), "Address should contain only hex characters");
}

#[test]
fn test_multiple_transactions_same_wallet() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    let chain_id = 1;
    
    // Create and sign multiple transactions with increasing nonces
    for nonce in 0..5 {
        let mut tx = Transaction::new(
            wallet.address,
            recipient,
            100 * (nonce + 1),  // different amounts
            1,                  // fee
            nonce,              // increasing nonce
            chain_id
        );
        
        wallet.sign_transaction(&mut tx)?;
        assert!(tx.verify(), "Transaction with nonce {} failed to verify", nonce);
    }
    
    Ok(())
}

#[test]
fn test_address_derivation() {
    // Create a wallet
    let wallet = Wallet::new();
    
    // Extract public key
    let public_key = &wallet.public_key;
    
    // Manually derive the address (SHA256 followed by RIPEMD160)
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;
    
    let mut sha = Sha256::new();
    sha.update(public_key);
    let hash1 = sha.finalize();
    
    let mut ripemd = Ripemd160::new();
    ripemd.update(hash1);
    let hash2 = ripemd.finalize();
    
    // Convert to array
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash2);
    
    // Compare with the wallet's address
    assert_eq!(wallet.address, address, "Manually derived address should match wallet address");
}

#[test]
fn test_transaction_with_max_values() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wallet = Wallet::new();
    let recipient = [0xFF; 20]; // All 1s
    let chain_id = u64::MAX;
    
    // Create a transaction with maximum values
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        u64::MAX,  // maximum amount
        u64::MAX,  // maximum fee
        u64::MAX,  // maximum nonce
        chain_id
    );
    
    // Sign and verify
    wallet.sign_transaction(&mut tx)?;
    assert!(tx.verify(), "Transaction with maximum values failed to verify");
    
    Ok(())
}

#[test]
fn test_transaction_with_zero_values() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wallet = Wallet::new();
    let recipient = [0; 20]; // All 0s
    let chain_id = 0;
    
    // Create a transaction with zero values
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        0,  // zero amount
        0,  // zero fee
        0,  // zero nonce
        chain_id
    );
    
    // Sign and verify
    wallet.sign_transaction(&mut tx)?;
    assert!(tx.verify(), "Transaction with zero values failed to verify");
    
    Ok(())
}

#[test]
fn test_different_wallets_same_transaction() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Create two different wallets
    let wallet1 = Wallet::new();
    let wallet2 = Wallet::new();
    
    // Create identical transaction data for both wallets
    let recipient = [1u8; 20];
    let chain_id = 1;
    
    // Create and sign transaction with wallet1
    let mut tx1 = Transaction::new(
        wallet1.address,
        recipient,
        100,
        1,
        0,
        chain_id
    );
    wallet1.sign_transaction(&mut tx1)?;
    
    // Create and sign transaction with wallet2
    let mut tx2 = Transaction::new(
        wallet2.address,
        recipient,
        100,
        1,
        0,
        chain_id
    );
    wallet2.sign_transaction(&mut tx2)?;
    
    // Each transaction should verify with its own signature
    assert!(tx1.verify(), "Transaction 1 failed to verify");
    assert!(tx2.verify(), "Transaction 2 failed to verify");
    
    // But signatures should be different
    assert_ne!(tx1.signature, tx2.signature, "Signatures should be different for different wallets");
    
    // Swap signatures - should fail verification
    let original_sig1 = tx1.signature.clone();
    tx1.signature = tx2.signature.clone();
    tx2.signature = original_sig1;
    
    assert!(!tx1.verify(), "Transaction 1 should not verify with wallet2's signature");
    assert!(!tx2.verify(), "Transaction 2 should not verify with wallet1's signature");
    
    Ok(())
}
