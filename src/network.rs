// src/network.rs
use serde::{Deserialize, Serialize};
use crate::types::{Block, Transaction, Hash};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::{info, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub block_height: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    // Handshake messages
    Hello { version: String, node_id: String },
    HelloAck { version: String, node_id: String },
    
    // Block messages
    GetHeight,
    Height { height: u64 },
    GetBlock { hash: Hash },
    Block { block: Block },
    NewBlock { block: Block },
    
    // Transaction messages
    NewTransaction { transaction: Transaction },
    GetTransactions,
    Transactions { transactions: Vec<Transaction> },
    
    // Mempool messages
    GetPendingTransactions { limit: usize },
    PendingTransactions { transactions: Vec<Transaction> },
    
    // Balance and history messages
    GetBalance { address: String },
    Balance { address: String, amount: u64 },
    GetTransactionHistory { address: String },
    TransactionHistory { address: String, transactions: Vec<TransactionInfo> },
    
    // Peer discovery
    GetPeers,
    Peers { peers: Vec<String> },
    
    // Mining messages
    GetTemplate,
    BlockTemplate { template: Block },
    SubmitBlock { block: Block },
    
    // General
    Ping,
    Pong,
    Error { message: String },
}

pub struct NetworkClient {
    pub stream: TcpStream,
    pub peer_address: String,
}

impl NetworkClient {
    pub async fn connect(address: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let stream = TcpStream::connect(address).await?;
        info!("Connected to peer: {}", address);
        
        Ok(NetworkClient {
            stream,
            peer_address: address.to_string(),
        })
    }
    
    pub async fn send_message(&mut self, message: &NetworkMessage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let serialized = serde_json::to_string(message)?;
        let length = serialized.len() as u32;
        
        self.stream.write_all(&length.to_be_bytes()).await?;
        self.stream.write_all(serialized.as_bytes()).await?;
        
        debug!("Sent message to {}: {:?}", self.peer_address, message);
        Ok(())
    }
    
    pub async fn receive_message(&mut self) -> Result<NetworkMessage, Box<dyn std::error::Error + Send + Sync>> {
        let mut length_bytes = [0u8; 4];
        self.stream.read_exact(&mut length_bytes).await?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        
        let mut buffer = vec![0u8; length];
        self.stream.read_exact(&mut buffer).await?;
        
        let message: NetworkMessage = serde_json::from_slice(&buffer)?;
        debug!("Received message from {}: {:?}", self.peer_address, message);
        
        Ok(message)
    }
    
    pub async fn handshake(&mut self, our_node_id: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let hello = NetworkMessage::Hello {
            version: "0.1.0".to_string(),
            node_id: our_node_id.to_string(),
        };
        self.send_message(&hello).await?;
        
        match self.receive_message().await? {
            NetworkMessage::HelloAck { version, node_id } => {
                info!("Handshake successful with peer {} (version: {})", node_id, version);
                Ok(node_id)
            }
            _ => Err("Invalid handshake response".into())
        }
    }
}
