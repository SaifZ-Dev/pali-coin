use pali_coin::wallet::Wallet;
use pali_coin::types::Transaction;

#[test]
fn test_transaction_signing() {
    // Create a new wallet for the sender
    let sender_wallet = Wallet::new();
    
    // Create a new wallet for the recipient
    let recipient_wallet = Wallet::new();
    
    // Create a transaction
    let mut tx = Transaction::new(
        sender_wallet.address,
        recipient_wallet.address,
        100, // amount
        1,   // fee
        1,   // nonce
        1    
);
    
    // Sign the transaction
sender_wallet.sign_transaction(&mut tx).expect("Failed to sign transaction");
    
    // Verify the signature
    assert!(!tx.signature.is_empty(), "Transaction signature should not be empty");
    
    // Create a transaction with mismatched addresses
    let mut invalid_tx = Transaction::new(
        recipient_wallet.address, // Using recipient as sender
        recipient_wallet.address,
        100,
        1,
        1,
        1,
    );
    
    // This should fail because we're using the wrong wallet to sign
    let result = sender_wallet.sign_transaction(&mut invalid_tx);
    assert!(result.is_err(), "Should fail when signing with wrong wallet");
}
