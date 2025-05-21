use pali_coin::wallet::Wallet;
use pali_coin::types::Transaction;

#[test]
fn test_ecdsa_signature() {
    // Create a wallet
    let wallet = Wallet::new();
    
    // Create a transaction
    let mut tx = Transaction::new(
        wallet.address,
        [1u8; 20], // Some recipient address
        100,       // Amount
        1,         // Fee
        1,         // Nonce
        1,    
);
    
    // Sign the transaction
    wallet.sign_transaction(&mut tx).unwrap();
    
    // The signature should not be empty
    assert!(!tx.signature.is_empty());
    assert!(!tx.public_key.is_empty());
    
    // Verify the transaction
    assert!(tx.verify(), "Transaction verification failed");
    
    // Modify the transaction - verification should fail
    let original_amount = tx.amount;
    tx.amount += 1;
    assert!(!tx.verify(), "Modified transaction should fail verification");
    
    // Create some data
    let data = b"Test data for signing";
    
    // Sign the data
    let signature = wallet.sign_data(data);
    
    // Verify the signature
    let valid = wallet.verify_signature(data, &signature);
    assert!(valid, "Signature should be valid");
    
    // Try with wrong data
    let wrong_data = b"Wrong data";
    let valid_wrong = wallet.verify_signature(wrong_data, &signature);
    assert!(!valid_wrong, "Signature should be invalid for wrong data");
}
