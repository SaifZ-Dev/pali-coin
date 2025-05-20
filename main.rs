mod types;
mod blockchain;
mod network;

use blockchain::Blockchain;
use network::{NetworkMessage, NetworkClient, generate_node_id, TransactionInfo};
use types::Transaction;
use clap::{Arg, Command};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use log::{info, error, debug};

type PeerMap = Arc<Mutex<HashMap<String, mpsc::Sender<NetworkMessage>>>>;

#[derive(Clone)]
pub struct Node {
    blockchain: Arc<Mutex<Blockchain>>,
    peers: PeerMap,
    node_id: String,
    message_sender: broadcast::Sender<NetworkMessage>,
}

impl Node {
    pub fn new(data_dir: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let blockchain = Arc::new(Mutex::new(Blockchain::new(data_dir)?));
        let peers = Arc::new(Mutex::new(HashMap::new()));
        let node_id = generate_node_id();
        let (message_sender, _) = broadcast::channel(1000);
        
        info!("Node initialized with ID: {}", node_id);
        
        Ok(Node {
            blockchain,
            peers,
            node_id,
            message_sender,
        })
    }
    
    pub fn get_blockchain_height(&self) -> u64 {
        self.blockchain.lock().unwrap().get_chain_height()
    }
    
    pub fn get_latest_block(&self) -> Option<types::Block> {
        self.blockchain.lock().unwrap().get_latest_block()
    }
    
    pub fn add_block(&self, block: types::Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut blockchain = self.blockchain.lock().unwrap();
            blockchain.add_block(block.clone())?;
        }
        
        let message = NetworkMessage::NewBlock { block };
        let _ = self.message_sender.send(message);
        
        Ok(())
    }
    
    pub fn create_block_template(&self) -> types::Block {
        let blockchain = self.blockchain.lock().unwrap();
        if let Some(latest_block) = blockchain.get_latest_block() {
            types::Block::new(
                latest_block.hash(),
                Vec::new(),
                latest_block.header.height + 1,
            )
        } else {
            types::Block::new([0; 32], Vec::new(), 0)
        }
    }
    
    pub fn get_balance(&self, address: &str) -> u64 {
        self.blockchain.lock().unwrap().get_balance(address)
    }
    
    // New method to get transaction history
    pub fn get_transaction_history(&self, address: &str) -> Vec<TransactionInfo> {
        let blockchain = self.blockchain.lock().unwrap();
        let chain = blockchain.get_chain();
        let mut transactions = Vec::new();
        
        // Scan the blockchain for transactions related to this address
        for block in chain {
            for tx in &block.transactions {
                let from_addr = hex::encode(tx.from);
                let to_addr = hex::encode(tx.to);
                
                // If the transaction involves this address (as sender or receiver)
                if from_addr == address || to_addr == address {
                    transactions.push(TransactionInfo {
                        hash: hex::encode(tx.hash()),
                        from: from_addr,
                        to: to_addr,
                        amount: tx.amount,
                        fee: tx.fee,
                        block_height: block.header.height,
                        timestamp: block.header.timestamp,
                    });
                }
            }
        }
        
        transactions
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let matches = Command::new("Pali Coin Node")
        .version("0.1.0")
        .about("Pali Coin blockchain node with network support")
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
                .default_value("./pali_data"),
        )
        .arg(
            Arg::new("connect")
                .short('c')
                .long("connect")
                .value_name("ADDRESS")
                .help("Connect to peer"),
        )
        .get_matches();

    let port = matches.get_one::<String>("port").unwrap().clone();
    let data_dir = matches.get_one::<String>("data-dir").unwrap().clone();
    let connect_to = matches.get_one::<String>("connect").cloned();

    info!("Starting Pali Coin node on port {}", port);

    let node = Node::new(&data_dir)?;
    let node_clone = node.clone();
    
    info!("Blockchain initialized with height: {}", node.get_blockchain_height());

    if let Some(peer_address) = connect_to {
        let node_for_peer = node.clone();
        tokio::spawn(async move {
            if let Err(e) = connect_to_peer(node_for_peer, &peer_address).await {
                error!("Failed to connect to peer {}: {}", peer_address, e);
            }
        });
    }

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    info!("Node listening on 127.0.0.1:{}", port);

    loop {
        let (socket, addr) = listener.accept().await?;
        info!("New peer connected: {}", addr);
        
        let node_for_peer = node_clone.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_peer(socket, node_for_peer).await {
                error!("Error handling peer {}: {}", addr, e);
            }
        });
    }
}

async fn connect_to_peer(node: Node, address: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = NetworkClient::connect(address).await?;
    
    let peer_id = client.handshake(&node.node_id).await?;
    info!("Connected to peer: {} ({})", peer_id, address);
    
    client.send_message(&NetworkMessage::GetHeight).await?;
    
    loop {
        match client.receive_message().await {
            Ok(message) => {
                handle_network_message(&node, message, &mut client).await?;
            }
            Err(e) => {
                error!("Error receiving from peer: {}", e);
                break;
            }
        }
    }
    
    Ok(())
}

async fn handle_peer(socket: TcpStream, node: Node) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Handle JSON protocol for miner communication
    let mut client = NetworkClient { stream: socket, peer_address: "incoming".to_string() };
    
    loop {
        match client.receive_message().await {
            Ok(message) => {
                match message {
                    NetworkMessage::Hello { version: _, node_id } => {
                        info!("Received handshake from: {}", node_id);
                        let response = NetworkMessage::HelloAck { 
                            version: "0.1.0".to_string(), 
                            node_id: node.node_id.clone() 
                        };
                        if let Err(e) = client.send_message(&response).await {
                            error!("Failed to send handshake response: {}", e);
                            break;
                        }
                    }
                    other => {
                        if let Err(e) = handle_network_message(&node, other, &mut client).await {
                            error!("Error handling message: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Error receiving message: {}", e);
                break;
            }
        }
    }
    
    info!("Peer disconnected");
    Ok(())
}

async fn handle_network_message(
    node: &Node,
    message: NetworkMessage,
    client: &mut NetworkClient,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match message {
        NetworkMessage::Height { height } => {
            let our_height = node.get_blockchain_height();
            info!("Peer has height {}, we have height {}", height, our_height);
        }
        NetworkMessage::NewBlock { block } => {
            info!("Received new block at height {}", block.header.height);
            if let Err(e) = node.add_block(block) {
                error!("Failed to add received block: {}", e);
            }
        }
        NetworkMessage::GetHeight => {
            let height = node.get_blockchain_height();
            client.send_message(&NetworkMessage::Height { height }).await?;
        }
        NetworkMessage::GetTemplate => {
            let template = node.create_block_template();
            client.send_message(&NetworkMessage::BlockTemplate { template }).await?;
        }
        NetworkMessage::SubmitBlock { block } => {
            info!("Received block submission at height {}", block.header.height);
            match node.add_block(block) {
                Ok(()) => info!("Block accepted and added to chain"),
                Err(e) => error!("Block rejected: {}", e),
            }
        }
        NetworkMessage::NewTransaction { transaction } => {
            info!("Received new transaction: {} -> {}, amount: {}", 
                hex::encode(transaction.from), 
                hex::encode(transaction.to), 
                transaction.amount
            );
            
            process_transaction(node, transaction).await?;
            
            // Send acknowledgement
            client.send_message(&NetworkMessage::Ping).await?;
        },
        NetworkMessage::GetBalance { address } => {
            info!("Received balance query for address: {}", address);
            
            // Get the balance from the blockchain
            let balance = node.get_balance(&address);
            
            // Send the balance back to the client
            client.send_message(&NetworkMessage::Balance { 
                address: address.clone(), 
                amount: balance 
            }).await?;
            
            info!("Sent balance response: {} PALI", balance);
        },
        NetworkMessage::GetTransactionHistory { address } => {
            info!("Received transaction history query for address: {}", address);
            
            // Get transaction history for this address
            let transactions = node.get_transaction_history(&address);
            
            // Send the transaction history back to the client
            client.send_message(&NetworkMessage::TransactionHistory { 
                address: address.clone(), 
                transactions 
            }).await?;
            
            info!("Sent transaction history ({} transactions)", transactions.len());
        },
        NetworkMessage::Ping => {
            client.send_message(&NetworkMessage::Pong).await?;
        }
        _ => {
            debug!("Unhandled message: {:?}", message);
        }
    }
    
    Ok(())
}

// Process a transaction by creating a new block with it
async fn process_transaction(
    node: &Node, 
    transaction: Transaction
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // In a real implementation, we would verify the transaction and add it to the mempool
    // For demonstration, we'll just create a new block with this transaction
    
    info!("Processing transaction: {} -> {}, amount: {}", 
        hex::encode(transaction.from), 
        hex::encode(transaction.to), 
        transaction.amount
    );
    
    // Create a block with this transaction
    let template = node.create_block_template();
    let mut new_block = template;
    new_block.transactions.push(transaction);
    
    // Attempt to mine and add the block
    info!("Creating new block with the transaction");
    if let Err(e) = node.add_block(new_block) {
        error!("Failed to add block with transaction: {}", e);
        return Err(e);
    }
    
    info!("Transaction successfully added to blockchain");
    Ok(())
