
use clap::{Arg, App, SubCommand};
use pali_coin::wallet::Wallet;
use std::path::Path;
use std::fs;
use zeroize::Zeroize;
use std::str::FromStr;
use std::process;
use serde::{Serialize, Deserialize};

// Define the EncryptedWallet structure here to detect encrypted wallets
#[derive(Serialize, Deserialize)]
struct EncryptedWallet {
    salt: String,
    nonce: String,
    encrypted_data: String,
}

fn main() {
    let matches = App::new("Pali Wallet")
        .version("1.0")
        .author("Your Name")
        .about("Pali Coin Wallet CLI")
        .arg(
            Arg::with_name("wallet")
                .short("w")
                .long("wallet")
                .value_name("FILE")
                .help("Sets the wallet file")
                .default_value("wallet.json")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .value_name("PASSWORD")
                .help("Wallet password for encryption/decryption")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("new")
                .about("Creates a new wallet")
                .arg(
                    Arg::with_name("encrypt")
                        .short("e")
                        .long("encrypt")
                        .help("Encrypt the wallet with a password"),
                ),
        )
        .subcommand(
            SubCommand::with_name("address")
                .about("Shows the wallet address"),
        )
        .subcommand(
            SubCommand::with_name("send")
                .about("Send coins to another address")
                .arg(
                    Arg::with_name("to")
                        .long("to")
                        .value_name("ADDRESS")
                        .help("Recipient address")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("amount")
                        .long("amount")
                        .value_name("AMOUNT")
                        .help("Amount to send")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("fee")
                        .long("fee")
                        .value_name("FEE")
                        .help("Transaction fee")
                        .default_value("1")
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("balance")
                .about("Check wallet balance"),
        )
        .get_matches();

    // Extract password if provided
    let password = matches.value_of("password");
    let wallet_path = matches.value_of("wallet").unwrap_or("wallet.json");

    if let Some(matches) = matches.subcommand_matches("new") {
        let encrypt = matches.is_present("encrypt");
        create_new_wallet(wallet_path, encrypt, password);
    } else if let Some(_) = matches.subcommand_matches("address") {
        show_wallet_address(wallet_path, password);
    } else if let Some(matches) = matches.subcommand_matches("send") {
        let to_address = matches.value_of("to").unwrap();
        let amount = matches.value_of("amount").unwrap();
        let fee = matches.value_of("fee").unwrap();
        
        send_transaction(wallet_path, to_address, amount, fee, password);
    } else if let Some(_) = matches.subcommand_matches("balance") {
        check_balance(wallet_path, password);
    } else {
        println!("No command specified. Use --help for usage information.");
    }
}

fn create_new_wallet(path: &str, encrypt: bool, password: Option<&str>) {
    let wallet = Wallet::new();
    println!("Created new wallet with address: {}", hex::encode(wallet.address));
    
    if encrypt {
        if let Some(pwd) = password {
            match wallet.save_encrypted(path, pwd) {
                Ok(_) => println!("Encrypted wallet saved to {}", path),
                Err(e) => {
                    eprintln!("Failed to save encrypted wallet: {}", e);
                    process::exit(1);
                }
            }
        } else {
            // Prompt for password if not provided
            println!("Enter password to encrypt wallet:");
            let mut pwd = String::new();
            std::io::stdin().read_line(&mut pwd).expect("Failed to read password");
            pwd = pwd.trim().to_string();
            
            match wallet.save_encrypted(path, &pwd) {
                Ok(_) => println!("Encrypted wallet saved to {}", path),
                Err(e) => {
                    eprintln!("Failed to save encrypted wallet: {}", e);
                    process::exit(1);
                }
            }
            
            // Zero out the password
            pwd.zeroize();
        }
    } else {
        match wallet.save(path) {
            Ok(_) => println!("Wallet saved to {} (unencrypted)", path),
            Err(e) => {
                eprintln!("Failed to save wallet: {}", e);
                process::exit(1);
            }
        }
    }
}

fn load_wallet(path: &str, password: Option<&str>) -> Result<Wallet, Box<dyn std::error::Error + Send + Sync>> {
    if Path::new(path).exists() {
        // Try to read as JSON first to check if it's encrypted
        let file_content = fs::read_to_string(path)?;
        if let Ok(_encrypted_wallet) = serde_json::from_str::<EncryptedWallet>(&file_content) {
            // This is an encrypted wallet
            if let Some(pwd) = password {
                Wallet::load_encrypted(path, pwd)
            } else {
                // Prompt for password
                println!("Encrypted wallet detected. Enter password:");
                let mut pwd = String::new();
                std::io::stdin().read_line(&mut pwd).expect("Failed to read password");
                pwd = pwd.trim().to_string();
                
                let result = Wallet::load_encrypted(path, &pwd);
                pwd.zeroize();
                result
            }
        } else {
            // Unencrypted wallet
            println!("Warning: Loading unencrypted wallet.");
            let wallet: Wallet = serde_json::from_str(&file_content)?;
            Ok(wallet)
        }
    } else {
        Err(format!("Wallet file {} not found", path).into())
    }
}

fn show_wallet_address(path: &str, password: Option<&str>) {
    match load_wallet(path, password) {
        Ok(wallet) => {
            println!("Wallet address: {}", hex::encode(wallet.address));
        },
        Err(e) => {
            eprintln!("Failed to load wallet: {}", e);
            process::exit(1);
        }
    }
}

fn send_transaction(path: &str, to: &str, amount: &str, fee: &str, password: Option<&str>) {
    // Parse amount and fee
    let amount_val = match u64::from_str(amount) {
        Ok(val) => val,
        Err(_) => {
            eprintln!("Invalid amount: {}", amount);
            process::exit(1);
        }
    };
    
    let fee_val = match u64::from_str(fee) {
        Ok(val) => val,
        Err(_) => {
            eprintln!("Invalid fee: {}", fee);
            process::exit(1);
        }
    };
    
    // Load wallet
    let wallet = match load_wallet(path, password) {
        Ok(wallet) => wallet,
        Err(e) => {
            eprintln!("Failed to load wallet: {}", e);
            process::exit(1);
        }
    };
    
    // Parse recipient address
    let to_bytes = match hex::decode(to) {
        Ok(bytes) => {
            if bytes.len() != 20 {
                eprintln!("Invalid address length: expected 20 bytes");
                process::exit(1);
            }
            let mut address = [0u8; 20];
            address.copy_from_slice(&bytes);
            address
        },
        Err(e) => {
            eprintln!("Invalid address format: {}", e);
            process::exit(1);
        }
    };
    
    // Connect to node and send transaction
    println!("Sending {} PALI to {} with fee {}", amount_val, to, fee_val);
    println!("Transaction sent!");
    
    // In a real implementation, you would:
    // 1. Create the transaction
    // 2. Sign it with the wallet's private key
    // 3. Connect to a node
    // 4. Submit the transaction
    // 5. Wait for confirmation
}

fn check_balance(path: &str, password: Option<&str>) {
    // Load wallet
    let wallet = match load_wallet(path, password) {
        Ok(wallet) => wallet,
        Err(e) => {
            eprintln!("Failed to load wallet: {}", e);
            process::exit(1);
        }
    };
    
    // In a real implementation, you would connect to a node and request the balance
    println!("Checking balance for address: {}", hex::encode(wallet.address));
    println!("Balance: 0 PALI"); // Placeholder
}
