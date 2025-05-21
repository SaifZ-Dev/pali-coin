// tests/integration_test.rs
use pali_coin::blockchain::Blockchain;
use pali_coin::wallet::Wallet;
use pali_coin::types::Transaction;
use pali_coin::secure_channel::SecureChannelManager;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

fn setup() {
    // Clean test directory
    let path = Path::new("test_data");
    if path.exists() {
        let _ = fs::remove_dir_all(path); // Use Result and ignore errors
    }
    fs::create_dir_all(path).expect("Failed to create test directory");
}
fn setup() {
    // Clean test directory
    let path = Path::new("test_data");
    if path.exists() {
        let _ = fs::remove_dir_all(path); // Use Result and ignore errors
    }
    fs::create_dir_all(path).expect("Failed to create test directory");
}

#[test]
fn test_transaction_validation_and_rejection() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new blockchain
    let mut blockchain = Blockchain::new("test_data", 1);
    
    // Create wallet for mining and fund it
    let miner_wallet = Wallet::new();
    blockchain.mine_block(&miner_wallet.address)?;
    
    // Create two wallets for testing transactions
    let wallet1 = Wallet::new();
    let wallet2 = Wallet::new();
    
    // Create a valid transaction (from miner to wallet1)
    let mut valid_tx = Transaction::new(
        miner_wallet.address,
        wallet1.address,
        10,  // amount
        1,   // fee
        0,   // nonce
        blockchain.chain_id,
    );
    miner_wallet.sign_transaction(&mut valid_tx)?;
    
    // This should succeed
    let result = blockchain.add_transaction(valid_tx.clone());
    assert!(result.is_ok(), "Valid transaction should be accepted");
    
    // Create an invalid transaction (insufficient balance)
    let mut invalid_tx1 = Transaction::new(
        wallet1.address,  // wallet1 has no funds
        wallet2.address,
        50,  // amount
        1,   // fee
        0,   // nonce
        blockchain.chain_id,
    );
    wallet1.sign_transaction(&mut invalid_tx1)?;
    
    // This should fail due to insufficient balance
    let result = blockchain.add_transaction(invalid_tx1.clone());
    assert!(result.is_err(), "Transaction with insufficient balance should be rejected");
    
    // Create an invalid transaction (invalid signature)
    let mut invalid_tx2 = Transaction::new(
        miner_wallet.address,  // Using miner's address (which has funds)
        wallet2.address,
        10,  // amount
        1,   // fee
        0,   // nonce
        blockchain.chain_id,
    );
    // Sign with the wrong wallet
    wallet1.sign_transaction(&mut invalid_tx2)?;
    
    // This should fail due to invalid signature
    let result = blockchain.add_transaction(invalid_tx2.clone());
    assert!(result.is_err(), "Transaction with invalid signature should be rejected");
    
    Ok(())
}

#[test]
fn test_chain_fork_resolution() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create blockchain and wallets
    let mut blockchain = Blockchain::new("test_data", 1);
    let miner1 = Wallet::new();
    let miner2 = Wallet::new();
    
    // Mine initial blocks
    blockchain.mine_block(&miner1.address)?;
    
    // Save current state
    let height = blockchain.height;
    let best_hash = blockchain.best_hash;
    
    // Mine two competing blocks
    let block1 = blockchain.mine_block(&miner1.address)?;
    println!("Mined block 1: {} at height {}", hex::encode(block1.hash()), block1.header.height);
    
    // Reset to previous state and mine another block
    blockchain.best_hash = best_hash;
    blockchain.height = height;
    let block2 = blockchain.mine_block(&miner2.address)?;
    println!("Mined block 2: {} at height {}", hex::encode(block2.hash()), block2.header.height);
    
    // Blocks should be different
    assert_ne!(block1.hash(), block2.hash(), "Blocks should be different");
    
    // The longest chain should win
    // In this case, it's the last one added
    assert_eq!(blockchain.best_hash, block2.hash(), "Second block should be the best hash");
    
    // Mine another block on top of the current chain
    let block3 = blockchain.mine_block(&miner2.address)?;
    println!("Mined block 3: {} at height {}", hex::encode(block3.hash()), block3.header.height);
    
    // Blockchain should have height 3
    assert_eq!(blockchain.height, 3, "Blockchain height should be 3");
    
    Ok(())
}

#[test]
fn test_blockchain_wallet_integration() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create blockchain and wallet
    let mut blockchain = Blockchain::new("test_data", 1);
    let wallet = Wallet::new();
    
    // Save wallet to a file
    wallet.save("test_data/wallet.json")?;
    
    // Mine a block
    blockchain.mine_block(&wallet.address)?;
    
    // Load the wallet
    let loaded_wallet = Wallet::load("test_data/wallet.json")?;
    
    // Verify it's the same wallet
    assert_eq!(wallet.address, loaded_wallet.address, "Loaded wallet should have the same address");
    
    // Check balance using the loaded wallet
    let balance = blockchain.get_balance(&loaded_wallet.address);
    assert!(balance > 0, "Loaded wallet should have a positive balance");
    
    // Create a transaction using the loaded wallet
    let recipient = [1u8; 20];
    let mut tx = Transaction::new(
        loaded_wallet.address,
        recipient,
        10,
        1,
        0,
        blockchain.chain_id
    );
    
    // Sign the transaction with the loaded wallet
    loaded_wallet.sign_transaction(&mut tx)?;
    
    // Add the transaction to the blockchain
    blockchain.add_transaction(tx.clone())?;
    
    // Mine a block to include the transaction
    blockchain.mine_block(&wallet.address)?;
    
    // Verify the recipient received the funds
    let recipient_balance = blockchain.get_balance(&recipient);
    assert_eq!(recipient_balance, 10, "Recipient should have received 10 coins");
    
    Ok(())
}

#[test]
fn test_hd_wallet_with_blockchain() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create an HD wallet
    let (wallet, seed_phrase) = Wallet::new_with_seed_phrase();
    
    // Create blockchain
    let mut blockchain = Blockchain::new("test_data", 1);
    
    // Mine a block to the wallet's address
    blockchain.mine_block(&wallet.address)?;
    
    // Get balance
    let balance = blockchain.get_balance(&wallet.address);
    assert!(balance > 0, "Wallet should have a positive balance");
    
    // Create a new wallet from the same seed phrase
    let recovered_wallet = Wallet::from_seed_phrase(&seed_phrase)?;
    
    // It should have the same address
    assert_eq!(wallet.address, recovered_wallet.address, "Recovered wallet should have the same address");
    
    // Should have the same balance
    let recovered_balance = blockchain.get_balance(&recovered_wallet.address);
    assert_eq!(balance, recovered_balance, "Recovered wallet should have the same balance");
    
    // Create a transaction from the recovered wallet
    let recipient = [1u8; 20];
    let mut tx = Transaction::new(
        recovered_wallet.address,
        recipient,
        10,
        1,
        0,
        blockchain.chain_id
    );
    
    // Sign with the recovered wallet
    recovered_wallet.sign_transaction(&mut tx)?;
    
    // Add the transaction
    blockchain.add_transaction(tx.clone())?;
    
    // Mine a block
    blockchain.mine_block(&recipient)?;
    
    // Verify the transaction was processed
    let new_balance = blockchain.get_balance(&recovered_wallet.address);
    assert_eq!(new_balance, balance - 11, "Wallet balance should be reduced by amount + fee");
    
    Ok(())
}

#[test]
fn test_secure_channel_with_blockchain() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create secure channel managers for two nodes
    let node1_manager = SecureChannelManager::new();
    let node2_manager = SecureChannelManager::new();
    
    // Get public keys
    let node1_pubkey = node1_manager.get_public_key();
    let node2_pubkey = node2_manager.get_public_key();
    
    // Create addresses
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    
    // Establish secure channels
    node1_manager.establish_channel(&node2_pubkey, addr2)?;
    node2_manager.establish_channel(&node1_pubkey, addr1)?;
    
    // Create blockchain and wallet
    let mut blockchain = Blockchain::new("test_data", 1);
    let wallet = Wallet::new();
    
    // Mine a block
    let block = blockchain.mine_block(&wallet.address)?;
    
    // Serialize the block
    let block_data = bincode::serialize(&block)?;
    
    // Node 1 encrypts the block data
    let encrypted = node1_manager.encrypt_message(addr2, &block_data)?;
    
    // Node 2 decrypts the block data
    let decrypted = node2_manager.decrypt_message(addr1, &encrypted)?;
    
    // Deserialize the block
    let received_block: pali_coin::types::Block = bincode::deserialize(&decrypted)?;
    
    // Verify it's the same block
    assert_eq!(block.hash(), received_block.hash(), "Block hashes should match after secure transmission");
    
    Ok(())
}

#[test]
fn test_multiple_transactions_and_mining() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create blockchain and wallets
    let mut blockchain = Blockchain::new("test_data", 1);
    let alice = Wallet::new();
    let bob = Wallet::new();
    let charlie = Wallet::new();
    
    // Mine initial blocks to give Alice some coins
    for _ in 0..3 {
        blockchain.mine_block(&alice.address)?;
    }
    
    // Get Alice's balance
    let alice_balance = blockchain.get_balance(&alice.address);
    println!("Alice's balance after mining: {}", alice_balance);
    
    // Create multiple transactions
    // Alice sends to Bob
    let mut tx1 = Transaction::new(
        alice.address,
        bob.address,
        20,
        2, // higher fee
        0,
        blockchain.chain_id
    );
    alice.sign_transaction(&mut tx1)?;
    
    // Alice sends to Charlie
    let mut tx2 = Transaction::new(
        alice.address,
        charlie.address,
        30,
        1, // lower fee
        1, // different nonce
        blockchain.chain_id
    );
    alice.sign_transaction(&mut tx2)?;
    
    // Add transactions to blockchain
    blockchain.add_transaction(tx1.clone())?;
    blockchain.add_transaction(tx2.clone())?;
    
    // Mine a block to include transactions
    // Transactions should be ordered by fee (highest first)
    let block = blockchain.mine_block(&charlie.address)?;
    
    // Verify both transactions are included
    let tx1_included = block.transactions.iter().any(|tx| tx.hash() == tx1.hash());
    let tx2_included = block.transactions.iter().any(|tx| tx.hash() == tx2.hash());
    
    assert!(tx1_included, "Transaction 1 should be included in the block");
    assert!(tx2_included, "Transaction 2 should be included in the block");
    
    // Verify transaction ordering
    let tx1_index = block.transactions.iter().position(|tx| tx.hash() == tx1.hash()).unwrap();
    let tx2_index = block.transactions.iter().position(|tx| tx.hash() == tx2.hash()).unwrap();
    
    // Transaction with higher fee should come first (after coinbase)
    assert!(tx1_index < tx2_index, "Transaction with higher fee should come first");
    
    // Check final balances
    let alice_final = blockchain.get_balance(&alice.address);
    let bob_final = blockchain.get_balance(&bob.address);
    let charlie_final = blockchain.get_balance(&charlie.address);
    
    assert_eq!(alice_final, alice_balance - 20 - 30 - 3, "Alice's final balance incorrect"); // -20 -30 -2fee -1fee
    assert_eq!(bob_final, 20, "Bob's final balance incorrect");
    assert_eq!(charlie_final, 30 + 50, "Charlie's final balance incorrect"); // 30 from Alice + 50 mining reward
    
    Ok(())
}

#[test]
fn test_blockchain_persistence_and_recovery() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create initial blockchain
    {
        let mut blockchain = Blockchain::new("test_data", 1);
        let wallet = Wallet::new();
        
        // Mine several blocks
        for _ in 0..5 {
            blockchain.mine_block(&wallet.address)?;
        }
        
        // Verify height
        assert_eq!(blockchain.height, 5, "Blockchain height should be 5");
        
        // Save a wallet to use later
        wallet.save("test_data/persistence_wallet.json")?;
    }
    
    // Create a new blockchain instance pointing to the same directory
    {
        let mut blockchain = Blockchain::new("test_data", 1);
        
        // Load the wallet
        let wallet = Wallet::load("test_data/persistence_wallet.json")?;
        
        // Verify the blockchain loaded the existing data
        assert_eq!(blockchain.height, 5, "Blockchain should load existing data");
        
        // Check wallet balance
        let balance = blockchain.get_balance(&wallet.address);
        assert!(balance > 0, "Wallet should have a balance from previously mined blocks");
        
        // Mine another block
        blockchain.mine_block(&wallet.address)?;
        
        // Verify height increased
        assert_eq!(blockchain.height, 6, "Blockchain height should now be 6");
    }
    
    // Create yet another blockchain instance to verify persistence
    {
        let blockchain = Blockchain::new("test_data", 1);
        
        // Verify height is still correct
        assert_eq!(blockchain.height, 6, "Blockchain height should persist as 6");
    }
    
    Ok(())
}

#[test]
fn test_transaction_validation_and_rejection() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create blockchain and wallets
    let mut blockchain = Blockchain::new("test_data", 1);
    let alice = Wallet::new();
    let bob = Wallet::new();
    let eve = Wallet::new(); // Attacker
    
    // Mine a block to give Alice some coins
    blockchain.mine_block(&alice.address)?;
    
    // Get Alice's balance
    let alice_balance = blockchain.get_balance(&alice.address);

// Check and fix how transactions are created in this test
let mut valid_tx = Transaction::new(
    sender_wallet.address,  // Make sure this is the correct sender address
    recipient_wallet.address,
    100,
    1,
    0,
    blockchain.chain_id
);

// Make sure you're signing with the correct wallet
sender_wallet.sign_transaction(&mut valid_tx)?;

// Then add the transaction to the blockchain
blockchain.add_transaction(valid_tx.clone())?;    
    alice.sign_transaction(&mut valid_tx)?;
    
    // This should validate successfully
    let result = blockchain.add_transaction(valid_tx.clone());
    assert!(result.is_ok(), "Valid transaction should validate successfully");
    
    // Create an invalid transaction (trying to spend more than available)
    let mut invalid_tx1 = Transaction::new(
        alice.address,
        bob.address,
        alice_balance + 100, // more than Alice has
        1,
        0,
        blockchain.chain_id
    );
    alice.sign_transaction(&mut invalid_tx1)?;
    
    // For invalid transactions
let result = blockchain.add_transaction(invalid_tx1.clone());
assert!(result.is_err(), "Invalid transaction should be rejected");
    
    // Create a transaction with Eve trying to spend Alice's coins
    let mut invalid_tx2 = Transaction::new(
        alice.address, // From Alice
        eve.address,   // To Eve
        20,
        1,
        0,
        blockchain.chain_id
    );
    eve.sign_transaction(&mut invalid_tx2)?; // Eve signs it
    
    // This should fail validation
    let result = blockchain.add_transaction(invalid_tx2.clone());
    assert!(result.is_err(), "Transaction should be rejected");
    
    // Add the valid transaction and mine a block
    blockchain.add_transaction(valid_tx.clone())?;
    blockchain.mine_block(&alice.address)?;
    
    // Verify Bob received the funds
    let bob_balance = blockchain.get_balance(&bob.address);
    assert_eq!(bob_balance, 20, "Bob should have received the funds");
    
    // Try to replay the same transaction
    let result = blockchain.add_transaction(valid_tx.clone());
    assert!(result.is_err(), "Replay of transaction should be rejected");
    
    Ok(())
}

#[test]
fn test_complex_transaction_scenario() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create blockchain and wallets
    let mut blockchain = Blockchain::new("test_data", 1);
    let alice = Wallet::new();
    let bob = Wallet::new();
    let charlie = Wallet::new();
    let dave = Wallet::new();
    
    // Mine initial blocks to give Alice and Bob some coins
    blockchain.mine_block(&alice.address)?;
    blockchain.mine_block(&bob.address)?;
    
    // Get initial balances
    let alice_initial = blockchain.get_balance(&alice.address);
    let bob_initial = blockchain.get_balance(&bob.address);
    
    // Create a series of transactions
    
    // 1. Alice sends to Charlie
    let mut tx1 = Transaction::new(
        alice.address,
        charlie.address,
        20,
        1,
        0,
        blockchain.chain_id
    );
    alice.sign_transaction(&mut tx1)?;
    blockchain.add_transaction(tx1)?;
    
    // 2. Bob sends to Dave
    let mut tx2 = Transaction::new(
        bob.address,
        dave.address,
        15,
        1,
        0,
        blockchain.chain_id
    );
    bob.sign_transaction(&mut tx2)?;
    blockchain.add_transaction(tx2)?;
    
    // Mine a block (Charlie mines it)
    blockchain.mine_block(&charlie.address)?;
    
    // Check intermediate balances
    let charlie_mid = blockchain.get_balance(&charlie.address);
    let dave_mid = blockchain.get_balance(&dave.address);
    
    assert_eq!(charlie_mid, 20 + 50, "Charlie should have 20 from Alice plus mining reward");
    assert_eq!(dave_mid, 15, "Dave should have 15 from Bob");
    
    // 3. Charlie sends to Alice
    let mut tx3 = Transaction::new(
        charlie.address,
        alice.address,
        30,
        1,
        0,
        blockchain.chain_id
    );
    charlie.sign_transaction(&mut tx3)?;
    blockchain.add_transaction(tx3)?;
    
    // 4. Dave sends to Bob
    let mut tx4 = Transaction::new(
        dave.address,
        bob.address,
        5,
        1,
        0,
        blockchain.chain_id
    );
    dave.sign_transaction(&mut tx4)?;
    blockchain.add_transaction(tx4)?;
    
    // Mine another block (Dave mines it)
    blockchain.mine_block(&dave.address)?;
    
    // Check final balances
    let alice_final = blockchain.get_balance(&alice.address);
    let bob_final = blockchain.get_balance(&bob.address);
    let charlie_final = blockchain.get_balance(&charlie.address);
    let dave_final = blockchain.get_balance(&dave.address);
    
    assert_eq!(alice_final, alice_initial - 20 - 1 + 30, "Alice's final balance incorrect");
    assert_eq!(bob_final, bob_initial - 15 - 1 + 5, "Bob's final balance incorrect");
    assert_eq!(charlie_final, 20 + 50 - 30 - 1, "Charlie's final balance incorrect");
    assert_eq!(dave_final, 15 - 5 - 1 + 50, "Dave's final balance incorrect");
    
    Ok(())
}
