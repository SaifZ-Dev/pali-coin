use pali_coin::wallet::Wallet;
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::io::{self, Write};
use std::fs;
use std::env;
use zeroize::Zeroize;

// Define the EncryptedWallet structure here to detect encrypted wallets
#[derive(Serialize, Deserialize)]
struct EncryptedWallet {
    salt: String,
    nonce: String,
    encrypted_data: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Simple command parsing
    if args.len() < 2 {
        println!("Usage: pali-wallet [command] [options]");
        println!("Commands: new, recover, address, send, balance, backup");
        return;
    }
    
    let command = &args[1];
    let wallet_path = if args.len() > 2 { &args[2] } else { "wallet.json" };
    
    match command.as_str() {
        "new" => {
            // Create a new wallet with seed phrase
            let (wallet, seed_phrase) = Wallet::new_with_seed_phrase();
            println!("Created new wallet with address: {}", hex::encode(wallet.address));
            println!("\nIMPORTANT: Write down your seed phrase and keep it in a safe place!");
            println!("Seed phrase: {}\n", seed_phrase);
            
            // Prompt for encryption
            print!("Encrypt wallet? (y/n): ");
            io::stdout().flush().unwrap();
            let mut encrypt = String::new();
            io::stdin().read_line(&mut encrypt).unwrap();
            
            if encrypt.trim().to_lowercase() == "y" {
                print!("Enter password: ");
                io::stdout().flush().unwrap();
                let mut password = String::new();
                io::stdin().read_line(&mut password).unwrap();
                
                match wallet.save_with_seed_phrase(wallet_path, &seed_phrase, &password.trim()) {
                    Ok(_) => println!("Encrypted wallet saved to {}", wallet_path),
                    Err(e) => eprintln!("Failed to save encrypted wallet: {}", e),
                }
                
                // Zero out sensitive data
                password.zeroize();
            } else {
                match wallet.save(wallet_path) {
                    Ok(_) => {
                        println!("Warning: Wallet saved unencrypted to {}", wallet_path);
                        println!("Anyone with access to this file can steal your funds.");
                    },
                    Err(e) => eprintln!("Failed to save wallet: {}", e),
                }
            }
            
            // Zero out the seed phrase from memory
            let mut seed_to_zero = seed_phrase.clone();
            seed_to_zero.zeroize();
        },
        "recover" => {
            if args.len() < 3 {
                println!("Usage: pali-wallet recover [wallet_path]");
                println!("You will be prompted to enter your seed phrase");
                return;
            }
            
            println!("Enter your seed phrase (24 words separated by spaces):");
            let mut seed_phrase = String::new();
            io::stdin().read_line(&mut seed_phrase).unwrap();
            seed_phrase = seed_phrase.trim().to_string();
            
            match Wallet::from_seed_phrase(&seed_phrase) {
                Ok(wallet) => {
                    println!("Wallet recovered successfully!");
                    println!("Address: {}", hex::encode(wallet.address));
                    
                    // Prompt for encryption
                    print!("Encrypt wallet? (y/n): ");
                    io::stdout().flush().unwrap();
                    let mut encrypt = String::new();
                    io::stdin().read_line(&mut encrypt).unwrap();
                    
                    if encrypt.trim().to_lowercase() == "y" {
                        print!("Enter password: ");
                        io::stdout().flush().unwrap();
                        let mut password = String::new();
                        io::stdin().read_line(&mut password).unwrap();
                        
                        match wallet.save_with_seed_phrase(wallet_path, &seed_phrase, &password.trim()) {
                            Ok(_) => println!("Encrypted wallet saved to {}", wallet_path),
                            Err(e) => eprintln!("Failed to save encrypted wallet: {}", e),
                        }
                        
                        // Zero out sensitive data
                        password.zeroize();
                    } else {
                        match wallet.save(wallet_path) {
                            Ok(_) => {
                                println!("Warning: Wallet saved unencrypted to {}", wallet_path);
                                println!("Anyone with access to this file can steal your funds.");
                            },
                            Err(e) => eprintln!("Failed to save wallet: {}", e),
                        }
                    }
                },
                Err(e) => eprintln!("Failed to recover wallet: {}", e),
            }
            
            // Zero out the seed phrase from memory
            seed_phrase.zeroize();
        },
        "address" => {
            // Show wallet address
            match load_wallet_with_seed(wallet_path) {
                Ok((wallet, _)) => println!("Wallet address: {}", hex::encode(wallet.address)),
                Err(e) => eprintln!("Failed to load wallet: {}", e),
            }
        },
        "send" => {
            if args.len() < 5 {
                println!("Usage: pali-wallet send [wallet_path] [to_address] [amount]");
                return;
            }
            
            let to_address = &args[3];
            let amount = match args[4].parse::<u64>() {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Invalid amount: {}", args[4]);
                    return;
                }
            };
            
            // Convert to address to bytes
            let to_bytes = match hex::decode(to_address) {
                Ok(bytes) => {
                    if bytes.len() != 20 {
                        eprintln!("Invalid address length: expected 20 bytes");
                        return;
                    }
                    let mut address = [0u8; 20];
                    address.copy_from_slice(&bytes);
                    address
                },
                Err(e) => {
                    eprintln!("Invalid address format: {}", e);
                    return;
                }
            };
            
            // Load wallet
            match load_wallet_with_seed(wallet_path) {
                Ok((wallet, _)) => {
                    // Create a transaction
                    let mut tx = pali_coin::types::Transaction::new(
                        wallet.address,
                        to_bytes,
                        amount,
                        1, // fee
                        pali_coin::wallet::generate_nonce(), // use random nonce
                        1,
                    );
                    
                    // Sign the transaction
                    match wallet.sign_transaction(&mut tx) {
                        Ok(_) => {
                            println!("Transaction created and signed successfully.");
                            println!("From: {}", hex::encode(wallet.address));
                            println!("To: {}", to_address);
                            println!("Amount: {} PALI", amount);
                            println!("Fee: 1 PALI");
                            println!("Signature: {}", hex::encode(&tx.signature));
                            
                            // In a real implementation, you would:
                            // 1. Connect to a node
                            // 2. Submit the transaction
                            // 3. Wait for confirmation
                            println!("Transaction sent! (simulated)");
                        },
                        Err(e) => eprintln!("Failed to sign transaction: {}", e),
                    }
                },
                Err(e) => eprintln!("Failed to load wallet: {}", e),
            }
        },
        "balance" => {
            // Show wallet balance
            match load_wallet_with_seed(wallet_path) {
                Ok((wallet, _)) => {
                    println!("Address: {}", hex::encode(wallet.address));
                    println!("Balance: 0 PALI (simulated)");
                },
                Err(e) => eprintln!("Failed to load wallet: {}", e),
            }
        },
        "backup" => {
            // Show seed phrase for backup
            match load_wallet_with_seed(wallet_path) {
                Ok((_, seed_phrase)) => {
                    println!("\nIMPORTANT: Write down your seed phrase and keep it in a safe place!");
                    println!("You can use this seed phrase to recover your wallet on any device.");
                    println!("\nSeed phrase: {}\n", seed_phrase);
                },
                Err(e) => eprintln!("Failed to load wallet: {}", e),
            }
        },
        _ => {
            println!("Unknown command: {}", command);
            println!("Available commands: new, recover, address, send, balance, backup");
        }
    }
}

fn load_wallet_with_seed(path: &str) -> Result<(Wallet, String), Box<dyn std::error::Error + Send + Sync>> {
    if Path::new(path).exists() {
        // Try to read as JSON first to check if it's encrypted
        let file_content = fs::read_to_string(path)?;
        if let Ok(_encrypted_wallet) = serde_json::from_str::<EncryptedWallet>(&file_content) {
            // This is an encrypted wallet
            print!("Encrypted wallet detected. Enter password: ");
            io::stdout().flush().unwrap();
            let mut password = String::new();
            io::stdin().read_line(&mut password).unwrap();
            
            // Try to load with seed phrase first
            let password_trimmed = password.trim();
            match Wallet::load_with_seed_phrase(path, password_trimmed) {
                Ok(result) => {
                    password.zeroize();
                    return Ok(result);
                }
                Err(_) => {
                    // If that fails, try regular wallet loading
                    match Wallet::load_encrypted(path, password_trimmed) {
                        Ok(wallet) => {
                            password.zeroize();
                            return Ok((wallet, "Seed phrase not available for this wallet".to_string()));
                        }
                        Err(e) => {
                            password.zeroize();
                            return Err(e);
                        }
                    }
                }
            }
        } else {
            // Unencrypted wallet
            println!("Warning: Loading unencrypted wallet.");
            let wallet: Wallet = serde_json::from_str(&file_content)?;
            return Ok((wallet, "Seed phrase not available for this wallet".to_string()));
        }
    } else {
        Err(format!("Wallet file {} not found", path).into())
    }
}
