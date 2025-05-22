// src/main.rs
use pali_coin::blockchain::Blockchain;
use pali_coin::types::{Block, Transaction};
use pali_coin::network::{NetworkMessage, NetworkClient};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use tokio::net::{TcpListener, TcpStream};
use log::{info, error, debug, warn};
use clap::{Arg, Command};

pub struct NodeService {
    blockchain: Arc<RwLock<Blockchain>>,
    mempool: Arc<RwLock<Vec<Transaction>>>,
    peers: Arc<RwLock<HashMap<String, NetworkClient>>>,
    chain_id: u64,
}

impl NodeService {
    pub fn new(data_dir: &str, chain_id: u64) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let blockchain = Blockchain::new(data_dir)?;
        
        Ok(NodeService {
            blockchain: Arc::new(RwLock::new(blockchain)),
            mempool: Arc::new(RwLock::new(Vec::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            chain_id,
        })
    }

    pub fn get_chain_height(&self) -> u64 {
        self.blockchain.read().unwrap().get_chain_height()
    }

    pub fn get_latest_block(&self) -> Option<Block> {
        self.blockchain.read().unwrap().get_latest_block()
    }

    pub fn create_block_template(&self, miner_address: &str) -> Block {
        self.blockchain.read().unwrap().create_block_template(miner_address)
    }

    pub fn get_balance(&self, address_str: &str) -> u64 {
        self.blockchain.read().unwrap().get_balance(address_str)
    }

    pub fn get_chain(&self) -> Vec<Block> {
        self.blockchain.read().unwrap().get_chain()
    }

    pub fn add_transaction_to_mempool(&self, transaction: Transaction) -> Result<(), String> {
        // Validate transaction before adding to mempool
        {
            let blockchain = self.blockchain.read().unwrap();
            if let Err(e) = blockchain.validate_transaction(&transaction) {
                return Err(format!("Invalid transaction: {}", e));
            }
        }

        // Check if transaction already exists in mempool
        let mut mempool = self.mempool.write().unwrap();
        let tx_hash = transaction.hash();
        
        if mempool.iter().any(|tx| tx.hash() == tx_hash) {
            return Err("Transaction already in mempool".to_string());
        }

        mempool.push(transaction);
        info!("Added transaction to mempool: {}", hex::encode(tx_hash));
        Ok(())
    }

    pub fn get_pending_transactions(&self, limit: usize) -> Vec<Transaction> {
        let mempool = self.mempool.read().unwrap();
        mempool.iter().take(limit).cloned().collect()
    }

    pub fn submit_block(&self, block: Block) -> Result<(), String> {
        let mut blockchain = self.blockchain.write().unwrap();
        
        match blockchain.add_block(block.clone()) {
            Ok(_) => {
                info!("Block {} accepted at height {}", hex::encode(block.hash()), block.header.height);
                
                // Remove transactions from mempool that are now in the block
                let mut mempool = self.mempool.write().unwrap();
                let block_tx_hashes: std::collections::HashSet<_> = block.transactions.iter()
                    .map(|tx| tx.hash())
                    .collect();
                
                mempool.retain(|tx| !block_tx_hashes.contains(&tx.hash()));
                
                Ok(())
            }
            Err(e) => {
                warn!("Block rejected: {}", e);
                Err(format!("Block rejected: {}", e))
            }
        }
    }

    pub async fn handle_network_message(&self, message: NetworkMessage) -> NetworkMessage {
        match message {
            NetworkMessage::GetHeight => {
                NetworkMessage::Height { height: self.get_chain_height() }
            }
            
            NetworkMessage::GetTemplate => {
                // Use a default mining address if none provided
                let template = self.create_block_template("0000000000000000000000000000000000000000");
                NetworkMessage::BlockTemplate { template }
            }
            
            NetworkMessage::GetPendingTransactions { limit } => {
                let transactions = self.get_pending_transactions(limit);
                NetworkMessage::PendingTransactions { transactions }
            }
            
            NetworkMessage::NewTransaction { transaction } => {
                match self.add_transaction_to_mempool(transaction) {
                    Ok(_) => NetworkMessage::Pong, // Success acknowledgment
                    Err(msg) => NetworkMessage::Error { message: msg },
                }
            }
            
            NetworkMessage::SubmitBlock { block } => {
                // Check if this block is still valid (not stale)
                let current_height = self.get_chain_height();
                
                if block.header.height <= current_height {
                    // Block is stale - chain has moved ahead
                    warn!("Rejecting stale block: block height {}, current chain height {}", 
                          block.header.height, current_height);
                    NetworkMessage::Error { 
                        message: format!("Stale block: chain has advanced to height {}", current_height) 
                    }
                } else if block.header.height > current_height + 1 {
                    // Block is too far ahead
                    warn!("Rejecting future block: block height {}, current chain height {}", 
                          block.header.height, current_height);
                    NetworkMessage::Error { 
                        message: format!("Block too far ahead: expected height {}", current_height + 1) 
                    }
                } else {
                    // Block height is correct, try to add it
                    match self.submit_block(block) {
                        Ok(_) => {
                            info!("Block accepted and added to chain");
                            NetworkMessage::Pong // Success acknowledgment
                        },
                        Err(msg) => {
                            warn!("Block rejected: {}", msg);
                            NetworkMessage::Error { message: msg }
                        },
                    }
                }
            }
            
            NetworkMessage::GetBalance { address } => {
                let balance = self.get_balance(&address);
                NetworkMessage::Balance { address, amount: balance }
            }
            
            NetworkMessage::GetTransactions => {
                let transactions = self.get_pending_transactions(100);
                NetworkMessage::Transactions { transactions }
            }
            
            NetworkMessage::Ping => NetworkMessage::Pong,
            
            _ => NetworkMessage::Error { 
                message: "Unsupported message type".to_string() 
            },
        }
    }
}

async fn handle_client(
    stream: TcpStream,
    node: Arc<NodeService>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer_addr = stream.peer_addr()?.to_string();
    info!("New connection from: {}", peer_addr);
    
    let mut client = NetworkClient { stream, peer_address: peer_addr.clone() };
    
    // Handle handshake
    match client.receive_message().await? {
        NetworkMessage::Hello { version, node_id } => {
            info!("Handshake from {} (version: {})", node_id, version);
            
            let response = NetworkMessage::HelloAck {
                version: "0.1.0".to_string(),
                node_id: "pali-node".to_string(),
            };
            client.send_message(&response).await?;
        }
        _ => {
            error!("Invalid handshake from {}", peer_addr);
            return Err("Invalid handshake".into());
        }
    }
    
    // Handle subsequent messages
    loop {
        match client.receive_message().await {
            Ok(message) => {
                debug!("Received message from {}: {:?}", peer_addr, message);
                let response = node.handle_network_message(message).await;
                
                if let Err(e) = client.send_message(&response).await {
                    error!("Failed to send response to {}: {}", peer_addr, e);
                    break;
                }
            }
            Err(e) => {
                debug!("Connection closed by {}: {}", peer_addr, e);
                break;
            }
        }
    }
    
    info!("Disconnected: {}", peer_addr);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let matches = Command::new("Pali Coin Node")
        .version("0.1.0")
        .about("Pali Coin blockchain node")
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Port to listen on")
                .default_value("8333"),
        )
        .arg(
            Arg::new("data-dir")
                .short('d')
                .long("data-dir")
                .value_name("DIR")
                .help("Data directory")
                .default_value("data"),
        )
        .get_matches();

    let port = matches.get_one::<String>("port").unwrap();
    let data_dir = matches.get_one::<String>("data-dir").unwrap();
    
    info!("Starting Pali Coin Node");
    info!("Data directory: {}", data_dir);
    
    let node = Arc::new(NodeService::new(data_dir, 1)?);
    
    info!("Blockchain initialized");
    info!("Chain height: {}", node.get_chain_height());
    
    let listen_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("Node listening on: {}", listen_addr);
    
    // Accept connections
    loop {
        let (stream, addr) = listener.accept().await?;
        let node_clone = Arc::clone(&node);
        
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, node_clone).await {
                error!("Error handling client {}: {}", addr, e);
            }
        });
    }
}
