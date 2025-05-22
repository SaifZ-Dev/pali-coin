use pali_coin::blockchain::Blockchain;
use pali_coin::wallet::Wallet;
use pali_coin::types::Transaction;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("Testing Pali Coin...");
    
    // Create a wallet
    let wallet = Wallet::new();
    println!("Created wallet with address: {}", hex::encode(wallet.address));
    
    // Initialize blockchain
    let blockchain = Blockchain::new("test_data", 1);
    println!("Initialized blockchain with chain ID: 1");
    
    // Create a transaction
    let recipient = [1u8; 20];
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        100,
        1,
        0,
        1
    );
    
    // Sign the transaction
    wallet.sign_transaction(&mut tx)?;
    println!("Created and signed transaction");
    
    println!("All tests completed successfully!");
    Ok(())
}
