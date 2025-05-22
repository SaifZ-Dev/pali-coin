// src/miner.rs
mod types;
mod network;

use network::{NetworkMessage, NetworkClient};
use types::meets_difficulty;
use clap::{Arg, Command};
use std::time::Duration;
use rand::Rng;
use log::{info, debug, error, warn};
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
    
    let mut block = match client.receive_message().await? {
        NetworkMessage::BlockTemplate { template } => template,
        NetworkMessage::Error { message } => {
            warn!("Failed to get block template: {}", message);
            return Err(message.into());
        }
        other => {
            warn!("Expected block template, got: {:?}", other);
            return Err("Expected block template".into());
        }
    };
    
    // Get pending transactions (limit to 10 per block)
    client.send_message(&NetworkMessage::GetPendingTransactions { limit: 10 }).await?;
    
    let pending_transactions = match client.receive_message().await? {
        NetworkMessage::PendingTransactions { transactions } => transactions,
        NetworkMessage::Transactions { transactions } => transactions,
        NetworkMessage::BlockTemplate { template: _ } => {
            // Sometimes the node sends another template instead of pending transactions
            // Just continue with empty transactions
            Vec::new()
        }
        other => {
            debug!("Unexpected response to GetPendingTransactions: {:?}", other);
            Vec::new()
        }
    };
    
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
    
    // Improved mining algorithm
    let difficulty = block.header.difficulty as usize;
    let start_time = std::time::Instant::now();
    let mut hashes = 0u64;
    let mut rng = rand::thread_rng();
    
    // Start with a random base nonce to avoid collisions with other miners
    let mut base_nonce: u64 = rng.gen();
    let mut nonce_offset = 0u64;
    
    loop {
        // Use incremental nonces with random base
        block.header.nonce = base_nonce.wrapping_add(nonce_offset);
        nonce_offset = nonce_offset.wrapping_add(1);
        
        let hash = block.hash();
        hashes += 1;
        
        // Check if it meets the difficulty requirement
        if meets_difficulty(&hash, difficulty) {
            let elapsed = start_time.elapsed();
            let hash_rate = if elapsed.as_secs() > 0 {
                hashes / elapsed.as_secs()
            } else {
                hashes
            };
            
            info!("Found valid nonce: {}", block.header.nonce);
            info!("Block hash: {}", hex::encode(hash));
            info!("Mined in {:.2}s at {} hashes/sec", elapsed.as_secs_f64(), hash_rate);
            
            // Submit the block
            client.send_message(&NetworkMessage::SubmitBlock { block: block.clone() }).await?;
            
            // Wait for response
            match client.receive_message().await? {
                NetworkMessage::Pong => {
                    info!("✅ Block accepted by network! Height: {}", block.header.height);
                    break;
                }
                NetworkMessage::Error { message } => {
                    if message.contains("Stale block") || message.contains("chain has advanced") {
                        warn!("⚠️  Block became stale during mining: {}", message);
                        info!("Getting fresh template...");
                        break; // Get a new template
                    } else if message.contains("Invalid block height") {
                        warn!("⚠️  Block height conflict: {}", message);
                        info!("Chain moved ahead, getting new template...");
                        break; // Get a new template
                    } else {
                        error!("❌ Block rejected: {}", message);
                        // Wait a bit before retrying
                        sleep(Duration::from_secs(2)).await;
                        break;
                    }
                }
                other => {
                    warn!("Unexpected response to block submission: {:?}", other);
                    break;
                }
            }
        }
        
        // Progress reporting and CPU management
        if hashes % 10000 == 0 {
            let elapsed = start_time.elapsed();
            let hash_rate = if elapsed.as_secs() > 0 {
                hashes / elapsed.as_secs()
            } else {
                hashes
            };
            
            debug!("Mining... {} hashes @ {} hashes/sec", hashes, hash_rate);
        }
        
        // Periodically yield to avoid CPU hogging
        if hashes % 1000 == 0 {
            tokio::task::yield_now().await;
        }
        
        // Randomize base nonce every 1M attempts to explore different spaces
        if nonce_offset % 1_000_000 == 0 && nonce_offset > 0 {
            let new_base: u64 = rng.gen();
            base_nonce = new_base;
            nonce_offset = 0;
            debug!("Switching to new nonce space: base {}", base_nonce);
        }
        
        // Check if we've been mining too long (block might be stale)
        let current_elapsed = start_time.elapsed();
        if current_elapsed.as_secs() > 30 {
            warn!("⚠️  Mining taking too long ({}s), getting fresh template...", current_elapsed.as_secs());
            break;
        }
    }
    
    Ok(())
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
    warn!("Using default address! Create a proper wallet.json file.");
    Ok("1234567890abcdef1234567890abcdef12345678".to_string())
}
