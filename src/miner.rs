mod types;
mod network;

use network::{NetworkMessage, NetworkClient};
use clap::{Arg, Command};
use std::time::Duration;
use rand::Rng;
use sha2::{Sha256, Digest};
use log::{info, debug, error};
use std::fs;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let matches = Command::new("Pali Coin Miner")
        .version("0.1.0")
        .about("Pali Coin miner with network support")
        .arg(
            Arg::new("node")
                .short('n')
                .long("node")
                .value_name("ADDRESS")
                .help("Node address")
                .default_value("127.0.0.1:8333"),
        )
        .arg(
            Arg::new("wallet")
                .short('w')
                .long("wallet")
                .value_name("WALLET_FILE")
                .help("Wallet file to receive rewards")
                .default_value("wallet.json"),
        )
        .get_matches();

    let node_address = matches.get_one::<String>("node").unwrap().clone();
    let wallet_file = matches.get_one::<String>("wallet").unwrap().clone();

    info!("Starting Pali Coin miner");
    info!("Connecting to node: {}", node_address);

    // Load the wallet to get the reward address
    let miner_address = get_wallet_address(&wallet_file)?;
    info!("Mining rewards will go to: {}", miner_address);

    let mut client = NetworkClient::connect(&node_address).await?;
    let node_id = client.handshake("pali-miner").await?;
    
    info!("Connected to node: {} ({})", node_id, node_address);

    // Mining loop
    loop {
        if let Err(e) = mine_block(&mut client, &miner_address).await {
            error!("Mining error: {}", e);
            // Wait a bit before retrying
            sleep(Duration::from_secs(5)).await;
        }
    }
}

async fn mine_block(client: &mut NetworkClient, miner_address: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get block template
    client.send_message(&NetworkMessage::GetTemplate).await?;
    
    let template = match client.receive_message().await? {
        NetworkMessage::BlockTemplate { template } => template,
        _ => return Err("Expected block template".into()),
    };
    
    // Get pending transactions (limit to 10 per block)
    client.send_message(&NetworkMessage::GetPendingTransactions { limit: 10 }).await?;
    
    let pending_transactions = match client.receive_message().await? {
        NetworkMessage::PendingTransactions { transactions } => transactions,
        NetworkMessage::Transactions { transactions } => transactions,
        _ => Vec::new(),
    };
    
    // Create a new block from the template
    let mut block = template;
    
    // Add pending transactions to the block
    for tx in pending_transactions {
        block.transactions.push(tx);
    }
    
    // Set the mining reward address in the coinbase transaction
    if !block.transactions.is_empty() && block.transactions[0].from == [0u8; 20] {
        // This is the coinbase transaction
        if let Ok(address_bytes) = hex::decode(miner_address) {
            if address_bytes.len() == 20 {
                block.transactions[0].to.copy_from_slice(&address_bytes);
                info!("Set mining reward recipient to {}", miner_address);
            }
        }
    }
    
    info!("Mining new block at height {} with {} transactions", 
          block.header.height, 
          block.transactions.len());
    
    // Simple proof-of-work: find a nonce that makes the hash start with some zeros
    let difficulty = block.header.difficulty as usize;
    let _target = vec![0u8; difficulty / 8 + 1];
    let mut rng = rand::thread_rng();
    
    let start_time = std::time::Instant::now();
    let mut hashes = 0;
    
    loop {
        // Set a random nonce
        block.header.nonce = rng.gen();
        
        // Calculate the hash
        let hash = block.hash();
        hashes += 1;
        
        // Check if it meets the difficulty requirement
        if meets_difficulty(&hash, difficulty) {
            let elapsed = start_time.elapsed();
            let hash_rate = if elapsed.as_secs() > 0 {
                hashes / elapsed.as_secs() as usize
            } else {
                hashes
            };
            
            info!("Found valid nonce: {}", block.header.nonce);
            info!("Block hash: {}", hex::encode(hash));
            info!("Mined at {} hashes/sec", hash_rate);
            
            // Submit the block to the node
            client.send_message(&NetworkMessage::SubmitBlock { block }).await?;
            
            // Wait for block to be processed
            sleep(Duration::from_millis(100)).await;
            
            break;
        }
        
        // Report progress
        if hashes % 10000 == 0 {
            let elapsed = start_time.elapsed();
            let hash_rate = if elapsed.as_secs() > 0 {
                hashes / elapsed.as_secs() as usize
            } else {
                hashes
            };
            
            debug!("Mining... {} hashes @ {} hashes/sec", hashes, hash_rate);
        }
        
        // Avoid CPU hogging
        if hashes % 1000 == 0 {
            sleep(Duration::from_millis(5)).await;
        }
    }
    
    Ok(())
}

fn meets_difficulty(hash: &[u8; 32], difficulty: usize) -> bool {
    // Check if the first 'difficulty' bits are zero
    let bytes = difficulty / 8;
    let bits = difficulty % 8;
    
    // Check whole bytes
    for i in 0..bytes {
        if hash[i] != 0 {
            return false;
        }
    }
    
    // Check remaining bits
    if bits > 0 && bytes < 32 {
        let mask = 0xFF << (8 - bits);
        if (hash[bytes] & mask) != 0 {
            return false;
        }
    }
    
    true
}

fn get_wallet_address(wallet_file: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Try to read the wallet file
    match fs::read_to_string(wallet_file) {
        Ok(content) => {
            // Parse wallet JSON
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(wallet_json) => {
                    // Extract address from wallet
                    if let Some(address) = wallet_json.get("address") {
                        if let Some(address_str) = address.as_str() {
                            return Ok(address_str.to_string());
                        }
                    }
                    
                    // If address not found in JSON, try to extract it from address field
                    if let Some(address_bytes) = wallet_json.get("address") {
                        if let Some(address_array) = address_bytes.as_array() {
                            let bytes: Vec<u8> = address_array.iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect();
                            
                            if bytes.len() == 20 {
                                return Ok(hex::encode(&bytes));
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to parse wallet JSON: {}", e);
                }
            }
        }
        Err(e) => {
            error!("Failed to read wallet file {}: {}", wallet_file, e);
        }
    }
    
    // Default address if wallet not found or invalid
    error!("Using default address! Mining rewards may be lost!");
    Ok("8471e37658593d6b29a10eeae54aad4d09ff9bcb".to_string()) // Replace with your address
}
