use pali_coin::wallet::Wallet;
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

#[test]
fn test_address_generation() {
    // Create a new wallet
    let wallet = Wallet::new();
    
    // Manually calculate the expected address
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(&wallet.public_key);
    let sha256_hash = sha256_hasher.finalize();
    
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(&sha256_hash);
    let ripemd_hash = ripemd_hasher.finalize();
    
    let mut expected_address = [0u8; 20];
    expected_address.copy_from_slice(&ripemd_hash);
    
    // Verify that the wallet's address matches our expected address
    assert_eq!(wallet.address, expected_address, 
               "Address generation does not match RIPEMD160(SHA256(publicKey))");
    
    // Test with a static private key for consistency
    let private_key = [42u8; 32]; // A simple test key
    
    // Create a wallet from this private key
    let static_wallet = Wallet::from_private_key(&private_key);
    
    // The address should be deterministic - same private key should always yield same address
    let static_wallet2 = Wallet::from_private_key(&private_key);
    assert_eq!(static_wallet.address, static_wallet2.address,
               "Address generation is not deterministic");
}
