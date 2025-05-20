mod types;
mod blockchain;
mod network;

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
            Command::new("history")
                .about("Show transaction history")
        )
        .subcommand(
            Command::new("info")
                .about("Show blockchain info")
        )
        .get_matches();

    let wallet_file = Path::new(matches.get_one::<String>("wallet-file").unwrap());
    let node_address = matches.get_one::<String>("node").unwrap();
    let _data_dir = matches.get_one::<String>("data-dir").unwrap(); // Unused, so prefix with underscore

    match matches.subcommand() {
        Some(("create", _)) => {
            create_wallet(wallet_file).await?;
        }
        Some(("address", _)) => {
            show_address(wallet_file).await?;
        }
        Some(("balance", _)) => {
            check_balance(wallet_file, node_address).await?;
        }
        Some(("send", sub_matches)) => {
            let to = sub_matches.get_one::<String>("to").unwrap();
            let amount: u64 = sub_matches.get_one::<String>("amount").unwrap().parse()?;
            let fee: u64 = sub_matches.get_one::<String>("fee").unwrap().parse()?;
            send_transaction(wallet_file, node_address, to, amount, fee).await?;
        }
        Some(("history", _)) => {
            get_transaction_history(wallet_file, node_address).await?;
        }
        Some(("info", _)) => {
            show_blockchain_info(node_address).await?;
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
    node_address: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let wallet = Wallet::from_file(wallet_file)?;
    let address = wallet.get_address_string();
    
    println!("Checking balance for address: {}", address);
    
    // Connect to node
    match NetworkClient::connect(node_address).await {
        Ok(mut client) => {
            let _node_id = client.handshake("pali-wallet").await?;
            println!("Connected to node: {}", node_address);
            
            // Send balance query
            client.send_message(&NetworkMessage::GetBalance { 
                address: address.clone() 
            }).await?;
            
            // Wait for response with timeout
            let timeout = Duration::from_secs(5);
            let start = std::time::Instant::now();
            
            while start.elapsed() < timeout {
                match client.receive_message().await {
                    Ok(NetworkMessage::Balance { address: addr, amount }) => {
                        if addr == address {
                            println!("Balance: {} PALI", amount);
                            return Ok(());
                        } else {
                            println!("Received balance for different address: {}", addr);
                        }
                    },
                    Ok(NetworkMessage::Error { message }) => {
                        println!("Error from node: {}", message);
                        return Ok(());
                    },
                    Ok(_) => {
                        // Ignore other message types, continue waiting
                        sleep(Duration::from_millis(100)).await;
                    },
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            
            println!("Timed out waiting for balance response");
        },
        Err(e) => {
            println!("Failed to connect to node: {}", e);
            println!("Please make sure the node is running at {}", node_address);
        }
    }
    
    Ok(())
}

async fn send_transaction(
    wallet_file: &Path,
    node_address: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let wallet = Wallet::from_file(wallet_file)?;
    
    // Connect to node
    match NetworkClient::connect(node_address).await {
        Ok(mut client) => {
            let _node_id = client.handshake("pali-wallet").await?;
            println!("Connected to node: {}", node_address);
            
            // First check if we have enough balance
            let from_address = wallet.get_address_string();
            client.send_message(&NetworkMessage::GetBalance { 
                address: from_address.clone() 
            }).await?;
            
            // Wait for balance response
            let mut balance: Option<u64> = None;
            let timeout = Duration::from_secs(5);
            let start = std::time::Instant::now();
            
            while start.elapsed() < timeout && balance.is_none() {
                match client.receive_message().await {
                    Ok(NetworkMessage::Balance { address: addr, amount }) => {
                        if addr == from_address {
                            balance = Some(amount);
                        }
                    },
                    Ok(_) => {
                        // Ignore other message types, continue waiting
                        sleep(Duration::from_millis(100)).await;
                    },
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            
            if balance.is_none() {
                return Err("Timed out waiting for balance response".into());
            }
            
            let balance = balance.unwrap();
            if balance < amount + fee {
                return Err(format!("Insufficient funds. Balance: {} PALI, Required: {} PALI", 
                                 balance, amount + fee).into());
            }
            
            // Parse recipient address
            match hex::decode(to_address) {
                Ok(to_bytes) => {
                    if to_bytes.len() != 20 {
                        return Err(format!("Invalid address length: expected 20 bytes, got {}", to_bytes.len()).into());
                    }
                    
                    let mut to_addr = [0u8; 20];
                    to_addr.copy_from_slice(&to_bytes);

                    // Create transaction
                    let mut transaction = Transaction::new(
                        wallet.address,
                        to_addr,
                        amount,
                        fee,
                        0, // In a real implementation, we'd get the nonce from the node
                    );

                    // Sign transaction with high security
                    wallet.sign_transaction(&mut transaction)?;

                    println!("Transaction created:");
                    println!("  From: {}", wallet.get_address_string());
                    println!("  To: {}", to_address);
                    println!("  Amount: {} PALI", amount);
                    println!("  Fee: {} PALI", fee);
                    println!("  Transaction hash: {}", hex::encode(transaction.hash()));

                    // Send transaction to node
                    client.send_message(&NetworkMessage::NewTransaction { 
                        transaction: transaction.clone() 
                    }).await?;
                    
                    println!("Transaction submitted to node.");
                    println!("Waiting for confirmation...");
                    
                    // Give the node some time to process
                    sleep(Duration::from_secs(2)).await;
                    
                    println!("Transaction sent successfully!");
                },
                Err(e) => {
                    return Err(format!("Invalid address format: '{}' is not a valid hex string. Error: {}", to_address, e).into());
                }
            }
        },
        Err(e) => {
            println!("Failed to connect to node: {}", e);
            println!("Please make sure the node is running at {}", node_address);
        }
    }

    Ok(())
}

async fn get_transaction_history(
    wallet_file: &Path,
    node_address: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let wallet = Wallet::from_file(wallet_file)?;
    let address = wallet.get_address_string();
    
    println!("Getting transaction history for address: {}", address);
    
    // Connect to node
    match NetworkClient::connect(node_address).await {
        Ok(mut client) => {
            let _node_id = client.handshake("pali-wallet").await?;
            println!("Connected to node: {}", node_address);
            
            // Send transaction history query
            client.send_message(&NetworkMessage::GetTransactionHistory { 
                address: address.clone() 
            }).await?;
            
            // Wait for response with timeout
            let timeout = Duration::from_secs(5);
            let start = std::time::Instant::now();
            
            while start.elapsed() < timeout {
                match client.receive_message().await {
                    Ok(NetworkMessage::TransactionHistory { address: addr, transactions }) => {
                        if addr == address {
                            if transactions.is_empty() {
                                println!("No transactions found for this address.");
                            } else {
                                println!("Transaction History:");
                                for (i, tx) in transactions.iter().enumerate() {
                                    println!("{}. Hash: {}", i+1, tx.hash);
                                    println!("   From: {}", tx.from);
                                    println!("   To: {}", tx.to);
                                    println!("   Amount: {} PALI", tx.amount);
                                    println!("   Fee: {} PALI", tx.fee);
                                    println!("   Block: {}", tx.block_height);
                                    println!("   Timestamp: {}", tx.timestamp);
                                    println!();
                                }
                            }
                            return Ok(());
                        } else {
                            println!("Received history for different address: {}", addr);
                        }
                    },
                    Ok(NetworkMessage::Error { message }) => {
                        println!("Error from node: {}", message);
                        return Ok(());
                    },
                    Ok(_) => {
                        // Ignore other message types, continue waiting
                        sleep(Duration::from_millis(100)).await;
                    },
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            
            println!("Timed out waiting for transaction history response");
        },
        Err(e) => {
            println!("Failed to connect to node: {}", e);
            println!("Please make sure the node is running at {}", node_address);
        }
    }
    
    Ok(())
}

async fn show_blockchain_info(
    node_address: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Getting blockchain information...");
    
    // Connect to node
    match NetworkClient::connect(node_address).await {
        Ok(mut client) => {
            let _node_id = client.handshake("pali-wallet").await?;
            println!("Connected to node: {}", node_address);
            
            // Get blockchain height
            client.send_message(&NetworkMessage::GetHeight).await?;
            
            // Wait for response with timeout
            let timeout = Duration::from_secs(5);
            let start = std::time::Instant::now();
            
            while start.elapsed() < timeout {
                match client.receive_message().await {
                    Ok(NetworkMessage::Height { height }) => {
                        println!("Blockchain Information:");
                        println!("  Chain height: {}", height);
                        
                        // We could request more info like latest block hash, etc.
                        // But for now we'll just show the height
                        
                        return Ok(());
                    },
                    Ok(_) => {
                        // Ignore other message types, continue waiting
                        sleep(Duration::from_millis(100)).await;
                    },
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            
            println!("Timed out waiting for blockchain info response");
        },
        Err(e) => {
            println!("Failed to connect to node: {}", e);
            println!("Please make sure the node is running at {}", node_address);
        }
    }
    
    Ok(())
}
