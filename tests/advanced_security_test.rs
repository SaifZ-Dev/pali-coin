// tests/advanced_security_test.rs
use pali_coin::hdwallet::HDWallet;
use pali_coin::types::Transaction;
use std::error::Error;
use std::fs;
use std::path::Path;

// Run before each test
fn setup() {
    // Clean test directory
    let path = Path::new("test_data");
    if path.exists() {
        fs::remove_dir_all(path).expect("Failed to clean test directory");
    }
    fs::create_dir_all(path).expect("Failed to create test directory");
}

#[test]
fn test_hd_wallet_derivation() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a seed
    let seed = [42u8; 32]; // Example deterministic seed
    
    // Create an HD wallet from seed
    let hd_wallet = HDWallet::new_from_seed(&seed)?;
    
    // Derive an account
    let account = hd_wallet.derive_account(0)?;
    
    // Check that the account has external and internal addresses
    assert!(!account.external_addresses.is_empty(), "External addresses should not be empty");
    assert!(!account.internal_addresses.is_empty(), "Internal addresses should not be empty");
    
    // Ensure consistent derivation
    let another_hd_wallet = HDWallet::new_from_seed(&seed)?;
    let another_account = another_hd_wallet.derive_account(0)?;
    
    // Compare the first address from each account
    assert_eq!(
        account.external_addresses[0].address,
        another_account.external_addresses[0].address,
        "Deterministic derivation should yield the same addresses"
    );
    
    Ok(())
}

#[test]
fn test_mnemonic_generation_and_recovery() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create an HD wallet with a mnemonic
    let hd_wallet = HDWallet::new_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")?;
    
    // Derive an account
    let account = hd_wallet.derive_account(0)?;
    
    // Ensure we can derive addresses
    assert!(!account.external_addresses.is_empty(), "External addresses should not be empty");
    
    // Ensure the mnemonic can be retrieved
    let mnemonic = hd_wallet.get_mnemonic().expect("Mnemonic should be available");
    assert_eq!(
        mnemonic,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "Retrieved mnemonic should match the original"
    );
    
    // Create a new wallet from the same mnemonic
    let recovered_wallet = HDWallet::new_from_mnemonic(mnemonic)?;
    let recovered_account = recovered_wallet.derive_account(0)?;
    
    // Compare the first address from each account
    assert_eq!(
        account.external_addresses[0].address,
        recovered_account.external_addresses[0].address,
        "Recovery from mnemonic should yield the same addresses"
    );
    
    Ok(())
}

#[test]
fn test_hd_wallet_transaction_signing() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create an HD wallet
    let hd_wallet = HDWallet::new_from_seed(&[42u8; 32])?;
    
    // Derive an account
    let account = hd_wallet.derive_account(0)?;
    
    // Get the first external address wallet
    let wallet = &account.external_addresses[0];
    
    // Create a transaction
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
    
    // Verify the signature
    assert!(tx.verify(), "Transaction signature verification failed");
    
    Ok(())
}

#[test]
fn test_multiple_accounts() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create an HD wallet
    let hd_wallet = HDWallet::new_from_seed(&[42u8; 32])?;
    
    // Derive multiple accounts
    let account0 = hd_wallet.derive_account(0)?;
    let account1 = hd_wallet.derive_account(1)?;
    let account2 = hd_wallet.derive_account(2)?;
    
    // Ensure the accounts have unique addresses
    let address0 = account0.external_addresses[0].address;
    let address1 = account1.external_addresses[0].address;
    let address2 = account2.external_addresses[0].address;
    
    assert_ne!(address0, address1, "Account 0 and 1 should have different addresses");
    assert_ne!(address0, address2, "Account 0 and 2 should have different addresses");
    assert_ne!(address1, address2, "Account 1 and 2 should have different addresses");
    
    // Ensure accounts can sign transactions
    for account in [&account0, &account1, &account2] {
        let wallet = &account.external_addresses[0];
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
        assert!(tx.verify(), "Transaction signature verification failed");
    }
    
    Ok(())
}

#[test]
fn test_seed_strength() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Test that different seeds produce different wallets
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];
    
    let hd_wallet1 = HDWallet::new_from_seed(&seed1)?;
    let hd_wallet2 = HDWallet::new_from_seed(&seed2)?;
    
    let account1 = hd_wallet1.derive_account(0)?;
    let account2 = hd_wallet2.derive_account(0)?;
    
    // Addresses should be different due to different seeds
    assert_ne!(
        account1.external_addresses[0].address,
        account2.external_addresses[0].address,
        "Different seeds should yield different addresses"
    );
    
    Ok(())
}
