#!/bin/bash
set -e

echo "Updating Pali Coin to fix transaction handling..."

# Update blockchain.rs
cat > src/blockchain.rs << 'EOL'
use crate::types::Block;
use rocksdb::{DB, Options};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::thread::sleep;
use std::time::Duration;

#[derive(Debug)]
pub struct Blockchain {
    db: Arc<DB>,
    chain: Arc<RwLock<Vec<Block>>>,
    utxo_set: Arc<RwLock<HashMap<String, u64>>>,
}

impl Blockchain {
    pub fn new(db_path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        
        // Add retry logic for database access
        let mut retries = 0;
        let max_retries = 5;
        let mut db = None;
        
        while retries < max_retries {
            match DB::open(&opts, db_path) {
                Ok(opened_db) => {
                    db = Some(Arc::new(opened_db));
                    break;
                }
                Err(e) => {
                    if retries == max_retries - 1 {
                        return Err(format!("Failed to open database after {} retries: {}", max_retries, e).into());
                    }
                    log::warn!("Failed to open database, retrying ({}/{}): {}", retries + 1, max_retries, e);
                    sleep(Duration::from_millis(500));
                    retries += 1;
                }
            }
        }
        
        let db = db.ok_or("Failed to open database")?;

        let mut blockchain = Blockchain {
            db,
            chain: Arc::new(RwLock::new(Vec::new())),
            utxo_set: Arc::new(RwLock::new(HashMap::new())),
        };

        blockchain.load_or_create_genesis()?;
        Ok(blockchain)
    }

    fn load_or_create_genesis(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self.db.get(b"latest_block_height")? {
            Some(height_bytes) => {
                let height = u64::from_le_bytes(height_bytes.try_into().unwrap());
                self.load_chain_from_db(height)?;
            }
            None => {
                self.create_genesis_block()?;
            }
        }
        Ok(())
    }

    fn create_genesis_block(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let genesis_block = Block::new([0; 32], Vec::new(), 0);
        self.add_block(genesis_block)?;
        log::info!("Created genesis block");
        Ok(())
    }

    pub fn add_block(&mut self, mut block: Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.is_valid_block(&block)? {
            return Err("Invalid block".into());
        }

        self.mine_block(&mut block);

        {
            let mut chain = self.chain.write().unwrap();
            chain.push(block.clone());
        }

        self.save_block_to_db(&block)?;
        self.update_utxo_set(&block)?;

        log::info!("Added block at height {}", block.header.height);
        Ok(())
    }

    fn is_valid_block(&self, block: &Block) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let chain = self.chain.read().unwrap();
        
        if let Some(last_block) = chain.last() {
            if block.header.prev_hash != last_block.hash() {
                return Ok(false);
            }
            if block.header.height != last_block.header.height + 1 {
                return Ok(false);
            }
        }

        for tx in &block.transactions {
            if !self.is_valid_transaction(tx)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn is_valid_transaction(&self, tx: &crate::types::Transaction) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // In a production system, we would:
        // 1. Verify signature
        // 2. Check that the sender has sufficient balance
        // 3. Check that the nonce is correct
        // For this example, we'll just check the signature format
        if tx.signature.len() != 64 && !tx.from.iter().all(|&b| b == 0) {
            return Ok(false);
        }
        
        // For mining rewards, allow transactions from address 0
        if tx.from.iter().all(|&b| b == 0) {
            return Ok(true);
        }
        
        // Check balance
        let from_addr = hex::encode(tx.from);
        let utxo_set = self.utxo_set.read().unwrap();
        let balance = utxo_set.get(&from_addr).copied().unwrap_or(0);
        
        if balance < tx.amount + tx.fee {
            log::warn!("Insufficient balance: {} has {} but needs {}", 
                      from_addr, balance, tx.amount + tx.fee);
            return Ok(false);
        }
        
        Ok(true)
    }

    fn mine_block(&self, block: &mut Block) {
        loop {
            if block.is_valid_proof_of_work() {
                break;
            }
            block.header.nonce += 1;
        }
        log::info!("Block mined with nonce: {}", block.header.nonce);
    }

    fn save_block_to_db(&self, block: &Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let serialized = bincode::serialize(block)?;
        let key = format!("block_{}", block.header.height);
        self.db.put(key.as_bytes(), &serialized)?;
        
        self.db.put(b"latest_block_height", &block.header.height.to_le_bytes())?;
        
        Ok(())
    }

    fn load_chain_from_db(&mut self, latest_height: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut chain = self.chain.write().unwrap();
        chain.clear();

        for height in 0..=latest_height {
            let key = format!("block_{}", height);
            if let Some(block_data) = self.db.get(key.as_bytes())? {
                let block: Block = bincode::deserialize(&block_data)?;
                chain.push(block);
            }
        }

        log::info!("Loaded {} blocks from database", chain.len());
        Ok(())
    }

    fn update_utxo_set(&self, block: &Block) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut utxo_set = self.utxo_set.write().unwrap();
        
        // Process transactions
        for tx in &block.transactions {
            // Format addresses as hex strings for storage
            let from_addr = hex::encode(tx.from);
            let to_addr = hex::encode(tx.to);
            
            // Deduct from sender
            if !from_addr.starts_with("0000000000000000") { // Not a mining reward
                let sender_balance = utxo_set.get(&from_addr).copied().unwrap_or(0);
                if sender_balance >= tx.amount + tx.fee {
                    utxo_set.insert(from_addr, sender_balance - tx.amount - tx.fee);
                } else {
                    return Err(format!("Insufficient funds: {} has only {} PALI", from_addr, sender_balance).into());
                }
            }
            
            // Add to recipient
            let recipient_balance = utxo_set.get(&to_addr).copied().unwrap_or(0);
            utxo_set.insert(to_addr, recipient_balance + tx.amount);
            
            log::info!("UTXO updated: {} -> {}, amount: {}, new balances: sender={}, recipient={}", 
                from_addr, to_addr, tx.amount, 
                utxo_set.get(&from_addr).copied().unwrap_or(0),
                utxo_set.get(&to_addr).copied().unwrap_or(0));
            
            // Add fee to miner (in a real implementation, this would go to the miner address)
            if let Some(last_block) = self.chain.read().unwrap().last() {
                if last_block.header.height > 0 {
                    let miner_addr = "system_fees"; // Simplified; should be the miner's address
                    let miner_balance = utxo_set.get(miner_addr).copied().unwrap_or(0);
                    utxo_set.insert(miner_addr.to_string(), miner_balance + tx.fee);
                }
            }
        }
        
        // Add block reward if this is not the genesis block
        if block.header.height > 0 {
            // Block reward should go to the miner's address
            // For simplicity, we'll use a system address in this example
            let miner_addr = "system_rewards"; // Simplified
            let reward = 50; // Fixed reward of 50 PALI per block
            
            let miner_balance = utxo_set.get(miner_addr).copied().unwrap_or(0);
            utxo_set.insert(miner_addr.to_string(), miner_balance + reward);
            
            log::info!("Mining reward: {} PALI to {}", reward, miner_addr);
        }
        
        Ok(())
    }

    pub fn get_latest_block(&self) -> Option<Block> {
        self.chain.read().unwrap().last().cloned()
    }

    pub fn get_chain_height(&self) -> u64 {
        self.chain.read().unwrap().len() as u64
    }

    pub fn get_balance(&self, address: &str) -> u64 {
        self.utxo_set.read().unwrap().get(address).copied().unwrap_or(0)
    }
}
EOL

# Update main.rs
cat > src/main.rs << 'EOL'
mod types;
mod blockchain;
mod network;

use blockchain::Blockchain;
use network::{NetworkMessage, NetworkClient, generate_node_id};
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
}
EOL

# Update wallet.rs
cat > src/wallet.rs << 'EOL'
mod types;
mod blockchain;
mod network;

use blockchain::Blockchain;
use network::{NetworkMessage, NetworkClient};
use types::{Transaction, Address};
use clap::{Arg, Command};
use std::fs;
use std::path::Path;
use tokio::time::sleep;
use tokio::time::Duration;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha256, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Wallet {
    // We don't serialize the actual Secp256k1 objects
    #[serde(skip_serializing, skip_deserializing)]
    secret_key: Option<SecretKey>,
    #[serde(skip_serializing, skip_deserializing)]
    public_key: Option<PublicKey>,
    
    // Store the bytes for serialization
    secret_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    address: Address,
}

impl Wallet {
    fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Use secp256k1 (same as Bitcoin)
        let secp = Secp256k1::new();
        let mut os_rng = OsRng::default();
        
        // Generate random bytes for the secret key (32 bytes)
        let mut random_bytes = [0u8; 32];
        os_rng.fill_bytes(&mut random_bytes);
        
        // Create secret key from random bytes
        let secret_key = SecretKey::from_slice(&random_bytes)?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        // Create address from public key (similar to Bitcoin)
        let address = Self::public_key_to_address(&public_key);
        
        Ok(Wallet {
            secret_key: Some(secret_key),
            public_key: Some(public_key),
            secret_key_bytes: secret_key[..].to_vec(),
            public_key_bytes: public_key.serialize().to_vec(),
            address,
        })
    }

    fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let contents = fs::read_to_string(path)?;
        let mut wallet: Wallet = serde_json::from_str(&contents)?;
        
        // Recreate the secret and public keys
        wallet.secret_key = Some(SecretKey::from_slice(&wallet.secret_key_bytes)?);
        wallet.public_key = Some(PublicKey::from_slice(&wallet.public_key_bytes)?);
        
        Ok(wallet)
    }

    fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }

    fn public_key_to_address(public_key: &PublicKey) -> Address {
        // Similar to Bitcoin: SHA-256 followed by taking first 20 bytes
        let serialized = public_key.serialize();
        let hash = Sha256::digest(&serialized);
        
        // Take first 20 bytes for the address
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[0..20]);
        address
    }

    fn sign_transaction(&self, tx: &mut Transaction) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let secp = Secp256k1::new();
        let secret_key = self.secret_key.as_ref().ok_or("Secret key not loaded")?;
        
        // Hash the transaction
        let tx_hash = tx.hash();
        
        // Create a message from the transaction hash
        let message = Message::from_slice(&tx_hash)?;
        
        // Sign the message
        let signature = secp.sign_ecdsa(&message, secret_key);
        
        // Store the signature in the transaction
        tx.signature = signature.serialize_compact().to_vec();
        
        Ok(())
    }

    fn get_address_string(&self) -> String {
        hex::encode(self.address)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let matches = Command::new("Pali Coin Wallet")
        .version("0.1.0")
        .about("Pali Coin wallet for managing addresses and transactions")
        .arg(
            Arg::new("wallet-file")
                .short('w')
                .long("wallet")
                .value_name("FILE")
                .help("Wallet file path")
                .default_value("./wallet.json"),
        )
        .arg(
            Arg::new("node")
                .short('n')
                .long("node")
                .value_name("ADDRESS")
                .help("Node address")
                .default_value("127.0.0.1:8333"),
        )
        .arg(
            Arg::new("data-dir")
                .short('d')
                .long("data-dir")
                .value_name("DIR")
                .help("Blockchain data directory")
                .default_value("./pali_data"),
        )
        .subcommand(
            Command::new("create")
                .about("Create a new wallet")
        )
        .subcommand(
            Command::new("address")
                .about("Show wallet address")
        )
        .subcommand(
            Command::new("balance")
                .about("Check balance")
        )
        .subcommand(
            Command::new("send")
                .about("Send Pali coins")
                .arg(
                    Arg::new("to")
                        .short('t')
                        .long("to")
                        .value_name("ADDRESS")
                        .help("Recipient address")
                        .required(true)
                )
                .arg(
                    Arg::new("amount")
                        .short('a')
                        .long("amount")
                        .value_name("AMOUNT")
                        .help("Amount to send")
                        .required(true)
                )
                .arg(
                    Arg::new("fee")
                        .short('f')
                        .long("fee")
                        .value_name("FEE")
                        .help("Transaction fee")
                        .default_value("1")
                )
        )
        .subcommand(
            Command::new("info")
                .about("Show blockchain info")
        )
        .get_matches();

    let wallet_file = Path::new(matches.get_one::<String>("wallet-file").unwrap());
    let node_address = matches.get_one::<String>("node").unwrap();
    let data_dir = matches.get_one::<String>("data-dir").unwrap();

    match matches.subcommand() {
        Some(("create", _)) => {
            create_wallet(wallet_file).await?;
        }
        Some(("address", _)) => {
            show_address(wallet_file).await?;
        }
        Some(("balance", _)) => {
            check_balance(wallet_file, data_dir, node_address).await?;
        }
        Some(("send", sub_matches)) => {
            let to = sub_matches.get_one::<String>("to").unwrap();
            let amount: u64 = sub_matches.get_one::<String>("amount").unwrap().parse()?;
            let fee: u64 = sub_matches.get_one::<String>("fee").unwrap().parse()?;
            send_transaction(wallet_file, node_address, to, amount, fee).await?;
        }
        Some(("info", _)) => {
            show_blockchain_info(data_dir).await?;
        }
        _ => {
            println!("No subcommand provided. Use --help for usage information.");
        }
    }

    Ok(())
}

async fn create_wallet(wallet_file: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if wallet_file.exists() {
        println!("Wallet file already exists: {}", wallet_file.display());
        return Ok(());
    }

    let wallet = Wallet::new()?;
    wallet.save_to_file(wallet_file)?;

    println!("Created new wallet!");
    println!("Address: {}", wallet.get_address_string());
    println!("Wallet saved to: {}", wallet_file.display());
    println!("⚠️  Keep your wallet file safe! It contains your private key.");

    Ok(())
}

async fn show_address(wallet_file: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let wallet = Wallet::from_file(wallet_file)?;
    println!("Wallet address: {}", wallet.get_address_string());
    Ok(())
}

async fn check_balance(
    wallet_file: &Path,
    data_dir: &str,
    node_address: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let wallet = Wallet::from_file(wallet_file)?;
    let address = wallet.get_address_string();
    
    // First try direct connection to node
    match NetworkClient::connect(node_address).await {
        Ok(mut client) => {
            let _node_id = client.handshake("pali-wallet").await?;
            println!("Connected to node: {}", node_address);
            println!("Checking balance for address: {}", address);
            
            // In a real implementation, we would query the node for balance
            // For now, we'll just read from local blockchain
            let blockchain = Blockchain::new(data_dir)?;
            let balance = blockchain.get_balance(&address);
            println!("Balance: {} PALI", balance);
        }
