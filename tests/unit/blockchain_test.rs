// tests/unit/blockchain_test.rs
use pali_coin::blockchain::Blockchain;
use pali_coin::wallet::Wallet;
use pali_coin::types::{Transaction, Block};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn setup() {
    // Clean up any existing test data
    let path = Path::new("blockchain_test_data");
    if path.exists() {
        fs::remove_dir_all(path).expect("Failed to clean test directory");
    }
    fs::create_dir_all(path).expect("Failed to create test directory");
}

#[test]
fn test_blockchain_creation() {
    setup();
    
    let chain_id = 1;
    let blockchain = Blockchain::new("blockchain_test_data", chain_id);
    
    // Verify initial state
    assert_eq!(blockchain.height, 0, "Initial height should be 0");
    assert_eq!(blockchain.chain_id, chain_id, "Chain ID should match");
}

#[test]
fn test_genesis_block() {
    setup();
    
    // Create a new blockchain
    let blockchain = Blockchain::new("blockchain_test_data", 1);
    
    // Get the genesis block - assuming get_block is implemented
    // Note: adjust this based on your actual API for accessing blocks
    let genesis_block = blockchain.get_block(&blockchain.genesis_hash)
        .expect("Failed to get genesis block");
    
    // Verify genesis block properties
    assert_eq!(genesis_block.header.height, 0, "Genesis block height should be 0");
    assert_eq!(genesis_block.header.prev_hash, [0u8; 32], "Genesis block previous hash should be zeros");
    assert!(!genesis_block.transactions.is_empty(), "Genesis block should have at least one transaction (coinbase)");
}

#[test]
fn test_block_creation() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new blockchain
    let mut blockchain = Blockchain::new("blockchain_test_data", 1);
    let wallet = Wallet::new();
    
    // Mine a block
    let block = blockchain.mine_block(&wallet.address)?;
    
    // Should have at least one transaction (coinbase)
    assert!(!block.transactions.is_empty(), "Block should have at least one transaction");
    
    // Height should be 1 (genesis block is 0)
    assert_eq!(block.header.height, 1, "Block height should be 1");
    
    // Previous hash should match genesis block
    assert_eq!(block.header.prev_hash, blockchain.genesis_hash, "Previous hash should match genesis block");
    
    // Blockchain height should be updated
    assert_eq!(blockchain.height, 1, "Blockchain height should be 1 after mining a block");
    
    // Block should exist in the blockchain
    let block_hash = block.hash();
    let retrieved_block = blockchain.get_block(&block_hash)
        .expect("Failed to get newly mined block");
    
    assert_eq!(retrieved_block.header.height, block.header.height, "Retrieved block height should match");
    
    Ok(())
}

#[test]
fn test_transaction_validation() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new blockchain and wallet
    let mut blockchain = Blockchain::new("blockchain_test_data", 1);
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    
    // Mine a block to get some coins
    blockchain.mine_block(&wallet.address)?;
    
    // Check balance
    let balance = blockchain.get_balance(&wallet.address);
    assert!(balance > 0, "Balance should be positive after mining");
    
    // Create a valid transaction
    let amount = 10;
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        amount,
        1,  // fee
        0,  // nonce
        blockchain.chain_id
    );
    
    wallet.sign_transaction(&mut tx)?;
    
    // Validate transaction
    let valid_result = blockchain.validate_transaction(&tx);
    assert!(valid_result.is_ok(), "Valid transaction should validate successfully");
    
    // Create an invalid transaction (too much amount)
    let mut invalid_tx = Transaction::new(
        wallet.address,
        recipient,
        balance + 100,  // more than balance
        1,
        0,
        blockchain.chain_id
    );
    
    wallet.sign_transaction(&mut invalid_tx)?;
    
    // Validate transaction - should fail
    let invalid_result = blockchain.validate_transaction(&invalid_tx);
    assert!(invalid_result.is_err(), "Invalid transaction should fail validation");
    
    Ok(())
}

#[test]
fn test_adding_transactions() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new blockchain and wallet
    let mut blockchain = Blockchain::new("blockchain_test_data", 1);
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    
    // Mine a block to get some coins
    blockchain.mine_block(&wallet.address)?;
    
    // Get balance
    let balance = blockchain.get_balance(&wallet.address);
    
    // Create a transaction
    let amount = 10;
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        amount,
        1,
        0,
        blockchain.chain_id
    );
    
    wallet.sign_transaction(&mut tx)?;
    
    // Add transaction to blockchain
    blockchain.add_transaction(tx.clone())?;
    
    // Mine a block to include the transaction
    let block = blockchain.mine_block(&wallet.address)?;
    
    // Block should contain our transaction
    let contains_tx = block.transactions.iter()
        .any(|t| t.hash() == tx.hash());
    
    assert!(contains_tx, "Block should contain our transaction");
    
    // Check balances
    let new_wallet_balance = blockchain.get_balance(&wallet.address);
    let recipient_balance = blockchain.get_balance(&recipient);
    
    // Wallet balance should decrease by amount + fee, but increase by mining reward
    assert!(new_wallet_balance < balance + 50, "Wallet balance should decrease by amount + fee, minus mining reward");
    
    // Recipient balance should increase by amount
    assert_eq!(recipient_balance, amount, "Recipient balance should equal the transferred amount");
    
    Ok(())
}

#[test]
fn test_double_spending() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new blockchain and wallet
    let mut blockchain = Blockchain::new("blockchain_test_data", 1);
    let wallet = Wallet::new();
    let recipient1 = [1u8; 20];
    let recipient2 = [2u8; 20];
    
    // Mine a block to get some coins
    blockchain.mine_block(&wallet.address)?;
    
    // Get balance
    let balance = blockchain.get_balance(&wallet.address);
    
    // Create first transaction (spending all funds)
    let mut tx1 = Transaction::new(
        wallet.address,wallet.address,
        recipient1,
        balance - 1, // all funds minus fee
        1,
        0,
        blockchain.chain_id
    );
    
    wallet.sign_transaction(&mut tx1)?;
    
    // Add first transaction
    blockchain.add_transaction(tx1.clone())?;
    
    // Create second transaction (trying to spend the same funds)
    let mut tx2 = Transaction::new(
        wallet.address,
        recipient2,
        balance - 1,
        1,
        0, // same nonce
        blockchain.chain_id
    );
    
    wallet.sign_transaction(&mut tx2)?;
    
    // Try to add second transaction - should fail
    let result = blockchain.add_transaction(tx2.clone());
    assert!(result.is_err(), "Double spend should be rejected");
    
    Ok(())
}

#[test]
fn test_multiple_blocks() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new blockchain and wallet
    let mut blockchain = Blockchain::new("blockchain_test_data", 1);
    let wallet = Wallet::new();
    
    // Mine several blocks
    let mut block_hashes = Vec::new();
    for _ in 0..5 {
        let block = blockchain.mine_block(&wallet.address)?;
        block_hashes.push(block.hash());
    }
    
    // Blockchain height should be 5
    assert_eq!(blockchain.height, 5, "Blockchain height should be 5");
    
    // Verify each block exists and has correct height
    for (i, hash) in block_hashes.iter().enumerate() {
        let block = blockchain.get_block(hash)
            .expect("Failed to get block");
        
        assert_eq!(block.header.height, i as u64 + 1, "Block height should match");
    }
    
    // Test getting the chain
    let chain = blockchain.get_chain();
    
    // Chain should have 6 blocks (genesis + 5 mined blocks)
    assert_eq!(chain.len(), 6, "Chain should have 6 blocks");
    
    // Verify block order
    for i in 0..chain.len() {
        assert_eq!(chain[i].header.height, i as u64, "Block height should match position in chain");
    }
    
    Ok(())
}

#[test]
fn test_chain_fork_resolution() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new blockchain and wallets
    let mut blockchain = Blockchain::new("blockchain_test_data", 1);
    let miner1 = Wallet::new();
    let miner2 = Wallet::new();
    
    // Mine initial block
    blockchain.mine_block(&miner1.address)?;
    
    // Save current state
    let height = blockchain.height;
    let best_hash = blockchain.best_hash;
    
    // Mine two competing blocks
    let block1 = blockchain.mine_block(&miner1.address)?;
    
    // Reset to previous state and mine another block
    blockchain.best_hash = best_hash;
    blockchain.height = height;
    let block2 = blockchain.mine_block(&miner2.address)?;
    
    // Blocks should be different
    assert_ne!(block1.hash(), block2.hash(), "Competing blocks should have different hashes");
    
    // The longest chain should win - in this case, it's the last one added
    assert_eq!(blockchain.best_hash, block2.hash(), "Best hash should match the last block added");
    
    Ok(())
}

#[test]
fn test_utxo_management() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new blockchain and wallets
    let mut blockchain = Blockchain::new("blockchain_test_data", 1);
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    
    // Mine a block to get some coins
    blockchain.mine_block(&wallet.address)?;
    
    // Get initial balance
    let initial_balance = blockchain.get_balance(&wallet.address);
    
    // Create a transaction
    let amount = 10;
    let mut tx = Transaction::new(
        wallet.address,
        recipient,
        amount,
        1,
        0,
        blockchain.chain_id
    );
    
    wallet.sign_transaction(&mut tx)?;
    
    // Add transaction and mine block
    blockchain.add_transaction(tx.clone())?;
    blockchain.mine_block(&wallet.address)?;
    
    // Check balances
    let new_wallet_balance = blockchain.get_balance(&wallet.address);
    let recipient_balance = blockchain.get_balance(&recipient);
    
    // Verify UTXO management
    assert!(new_wallet_balance < initial_balance, "Wallet balance should decrease");
    assert_eq!(recipient_balance, amount, "Recipient should receive the exact amount");
    
    // Create another transaction from recipient back to wallet
    let mut tx2 = Transaction::new(
        recipient,
        wallet.address,
        5, // send half back
        1,
        0,
        blockchain.chain_id
    );
    
    // Create a wallet for the recipient to sign the transaction
    let recipient_wallet = Wallet::from_private_key(&[0u8; 32]); // This is just for testing
    // In a real scenario, you'd need the actual private key for the recipient
    
    // Assuming we can forcefully set the address for testing
    let mut recipient_wallet_with_address = recipient_wallet;
    recipient_wallet_with_address.address = recipient;
    
    recipient_wallet_with_address.sign_transaction(&mut tx2)?;
    
    // Add transaction and mine block
    blockchain.add_transaction(tx2.clone())?;
    blockchain.mine_block(&wallet.address)?;
    
    // Check final balances
    let final_wallet_balance = blockchain.get_balance(&wallet.address);
    let final_recipient_balance = blockchain.get_balance(&recipient);
    
    // Verify final UTXO state
    assert!(final_wallet_balance > new_wallet_balance, "Wallet balance should increase after receiving funds back");
    assert_eq!(final_recipient_balance, 4, "Recipient should have 4 coins left (10 - 5 - 1 fee)");
    
    Ok(())
}

#[test]
fn test_difficulty_adjustment() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a new blockchain with a short adjustment period for testing
    let mut blockchain = Blockchain::new("blockchain_test_data", 1);
    
    // Initial difficulty
    let initial_difficulty = blockchain.current_difficulty;
    
    // Mine several blocks quickly to trigger difficulty adjustment
    for _ in 0..10 {
        blockchain.mine_block(&[0u8; 20])?;
    }
    
    // Check if difficulty was adjusted
    // Note: This test assumes your blockchain adjusts difficulty after some number of blocks
    // You may need to adjust this test based on your actual implementation
    if blockchain.height % blockchain.difficulty_adjustment_interval == 0 {
        assert_ne!(blockchain.current_difficulty, initial_difficulty, 
            "Difficulty should be adjusted after mining multiple blocks quickly");
    }
    
    Ok(())
}

#[test]
fn test_blockchain_persistence() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a blockchain and mine some blocks
    {
        let mut blockchain = Blockchain::new("blockchain_test_data", 1);
        let wallet = Wallet::new();
        
        // Mine a few blocks
        for _ in 0..3 {
            blockchain.mine_block(&wallet.address)?;
        }
        
        // Blockchain height should be 3
        assert_eq!(blockchain.height, 3, "Blockchain height should be 3");
    }
    
    // Create a new blockchain instance pointing to the same data directory
    {
        let blockchain = Blockchain::new("blockchain_test_data", 1);
        
        // Blockchain should load the existing data
        assert_eq!(blockchain.height, 3, "Blockchain should load existing data");
        
        // Get the chain
        let chain = blockchain.get_chain();
        assert_eq!(chain.len(), 4, "Chain should have 4 blocks (genesis + 3 mined)");
    }
    
    Ok(())
}

#[test]
fn test_mempool_management() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a blockchain and wallet
    let mut blockchain = Blockchain::new("blockchain_test_data", 1);
    let wallet = Wallet::new();
    let recipient = [1u8; 20];
    
    // Mine a block to get some coins
    blockchain.mine_block(&wallet.address)?;
    
    // Create several transactions
    let mut transactions = Vec::new();
    for i in 0..5 {
        let mut tx = Transaction::new(
            wallet.address,
            recipient,
            10,
            i + 1, // increasing fees
            i as u64, // different nonces
            blockchain.chain_id
        );
        
        wallet.sign_transaction(&mut tx)?;
        transactions.push(tx);
    }
    
    // Add transactions to the blockchain
    for tx in transactions.iter() {
        blockchain.add_transaction(tx.clone())?;
    }
    
    // Mempool should have 5 transactions
    assert_eq!(blockchain.mempool.len(), 5, "Mempool should have 5 transactions");
    
    // Mine a block - should include transactions ordered by fee
    let block = blockchain.mine_block(&wallet.address)?;
    
    // Mempool should be empty now
    assert!(blockchain.mempool.is_empty(), "Mempool should be empty after mining");
    
    // Block should contain all 5 transactions plus coinbase
    assert_eq!(block.transactions.len(), 6, "Block should contain all transactions plus coinbase");
    
    // Verify transactions are ordered by fee (highest fee first)
    for i in 1..block.transactions.len() - 1 {
        assert!(block.transactions[i].fee >= block.transactions[i+1].fee, 
            "Transactions should be ordered by fee (highest first)");
    }
    
    Ok(())
}

#[test]
fn test_block_timestamp_validation() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a blockchain
    let mut blockchain = Blockchain::new("blockchain_test_data", 1);
    
    // Current time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Create a block with a future timestamp
    let mut block = blockchain.create_block_template(&[0u8; 20]);
    block.header.timestamp = now + 7200; // 2 hours in the future
    
    // Validate the block - should fail
    let result = blockchain.validate_block(&block);
    assert!(result.is_err(), "Block with future timestamp should be rejected");
    
    // Create a block with a valid timestamp
    let mut valid_block = blockchain.create_block_template(&[0u8; 20]);
    valid_block.header.timestamp = now;
    
    // Validate the block - should succeed
    let valid_result = blockchain.validate_block(&valid_block);
    assert!(valid_result.is_ok(), "Block with valid timestamp should be accepted");
    
    Ok(())
}

#[test]
fn test_concurrent_mining() -> Result<(), Box<dyn Error + Send + Sync>> {
    setup();
    
    // Create a shared blockchain
    let blockchain = std::sync::Arc::new(std::sync::Mutex::new(
        Blockchain::new("blockchain_test_data", 1)
    ));
    
    // Create two miners
    let miner1 = Wallet::new();
    let miner2 = Wallet::new();
    
    // Clone Arc for threads
    let blockchain_clone1 = blockchain.clone();
    let blockchain_clone2 = blockchain.clone();
    let address1 = miner1.address;
    let address2 = miner2.address;
    
    // Start two mining threads
    let handle1 = thread::spawn(move || {
        for _ in 0..3 {
            let mut bc = blockchain_clone1.lock().unwrap();
            let _ = bc.mine_block(&address1);
            // Release lock and sleep to give other thread a chance
            drop(bc);
            thread::sleep(Duration::from_millis(10));
        }
    });
    
    let handle2 = thread::spawn(move || {
        for _ in 0..3 {
            let mut bc = blockchain_clone2.lock().unwrap();
            let _ = bc.mine_block(&address2);
            // Release lock and sleep
            drop(bc);
            thread::sleep(Duration::from_millis(10));
        }
    });
    
    // Wait for both threads to complete
    handle1.join().unwrap();
    handle2.join().unwrap();
    
    // Check final blockchain state
    let final_blockchain = blockchain.lock().unwrap();
    
    // Should have mined 6 blocks total
    assert_eq!(final_blockchain.height, 6, "Blockchain height should be 6");
    
    // Count blocks mined by each miner
    let chain = final_blockchain.get_chain();
    let miner1_blocks = chain.iter()
        .filter(|block| !block.transactions.is_empty() && 
                block.transactions[0].to == address1)
        .count();
    
    let miner2_blocks = chain.iter()
        .filter(|block| !block.transactions.is_empty() && 
                block.transactions[0].to == address2)
        .count();
    
    // Both miners should have mined some blocks
    assert!(miner1_blocks > 0, "Miner 1 should have mined at least one block");
    assert!(miner2_blocks > 0, "Miner 2 should have mined at least one block");
    assert_eq!(miner1_blocks + miner2_blocks, 6, "Total blocks mined should be 6");
    
    Ok(())
}
