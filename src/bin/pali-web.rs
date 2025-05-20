use warp::{Filter, Rejection, Reply};
use serde_json::json;
use handlebars::Handlebars;
use std::net::SocketAddr;
use warp::filters::body::json;

// Import from your library instead of local modules
use pali_coin::network::{NetworkMessage, NetworkClient};

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init();

    // Create Handlebars instance and register templates
    let mut hb = Handlebars::new();
    
    // Register template files
    hb.register_template_file("index", "templates/index.html").expect("Failed to register index template");
    hb.register_template_file("wallet", "templates/wallet.html").expect("Failed to register wallet template");
    
    // Setup node connection info
    let node_address = "127.0.0.1:8333";
    let hb = std::sync::Arc::new(hb);
    
    // API routes
    let api = warp::path("api");
    
    // Get balance
    let balance = api.and(warp::path("balance"))
        .and(warp::path::param())
        .and_then(move |address: String| {
            let node_addr = node_address.to_string();
            async move {
                get_balance(address, &node_addr).await
            }
        });
    
    // Get blockchain info
    let info = api.and(warp::path("info"))
        .and_then(move || {
            let node_addr = node_address.to_string();
            async move {
                get_blockchain_info(&node_addr).await
            }
        });
    
    // Get transaction history
    let history = api.and(warp::path("history"))
        .and(warp::path::param())
        .and_then(move |address: String| {
            let node_addr = node_address.to_string();
            async move {
                get_history(address, &node_addr).await
            }
        });
    
    // Send transaction
    let send_tx = api.and(warp::path("send"))
        .and(warp::post())
        .and(json())
        .and_then(move |tx_data: serde_json::Value| {
            let node_addr = node_address.to_string();
            async move {
                send_transaction(tx_data, &node_addr).await
            }
        });
    
    // Page routes
    let hb_clone = hb.clone();
    let index = warp::path::end()
        .and(warp::get())
        .map(move || {
            let hb = hb_clone.clone();
            match hb.render("index", &json!({})) {
                Ok(html) => warp::reply::html(html),
                Err(_) => warp::reply::html("Template rendering error".to_string()),
            }
        });
    
    let hb_clone = hb.clone();
    let wallet_page = warp::path("wallet")
        .and(warp::get())
        .map(move || {
            let hb = hb_clone.clone();
            match hb.render("wallet", &json!({})) {
                Ok(html) => warp::reply::html(html),
                Err(_) => warp::reply::html("Template rendering error".to_string()),
            }
        });
    
    // Combine all routes
    let routes = balance
        .or(info)
        .or(history)
        .or(send_tx)
        .or(index)
        .or(wallet_page);
    
    println!("Starting Pali Coin web interface at http://localhost:3000");
    
    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    warp::serve(routes).run(addr).await;
}

async fn get_balance(address: String, node_address: &str) -> Result<impl Reply, Rejection> {
    match NetworkClient::connect(node_address).await {
        Ok(mut client) => {
            if let Ok(_) = client.handshake("pali-web").await {
                if let Ok(_) = client.send_message(&NetworkMessage::GetBalance { 
                    address: address.clone() 
                }).await {
                    match client.receive_message().await {
                        Ok(NetworkMessage::Balance { address: addr, amount }) => {
                            return Ok(warp::reply::json(&json!({
                                "address": addr,
                                "balance": amount
                            })));
                        },
                        _ => {}
                    }
                }
            }
        },
        Err(_) => {}
    }
    
    Ok(warp::reply::json(&json!({
        "error": "Failed to connect to node"
    })))
}

async fn get_blockchain_info(node_address: &str) -> Result<impl Reply, Rejection> {
    match NetworkClient::connect(node_address).await {
        Ok(mut client) => {
            if let Ok(_) = client.handshake("pali-web").await {
                if let Ok(_) = client.send_message(&NetworkMessage::GetHeight).await {
                    match client.receive_message().await {
                        Ok(NetworkMessage::Height { height }) => {
                            return Ok(warp::reply::json(&json!({
                                "height": height,
                                "status": "ok"
                            })));
                        },
                        _ => {}
                    }
                }
            }
        },
        Err(_) => {}
    }
    
    Ok(warp::reply::json(&json!({
        "error": "Failed to connect to node"
    })))
}

async fn get_history(address: String, node_address: &str) -> Result<impl Reply, Rejection> {
    match NetworkClient::connect(node_address).await {
        Ok(mut client) => {
            if let Ok(_) = client.handshake("pali-web").await {
                if let Ok(_) = client.send_message(&NetworkMessage::GetTransactionHistory { 
                    address: address.clone() 
                }).await {
                    match client.receive_message().await {
                        Ok(NetworkMessage::TransactionHistory { address: addr, transactions }) => {
                            return Ok(warp::reply::json(&json!({
                                "address": addr,
                                "transactions": transactions
                            })));
                        },
                        _ => {}
                    }
                }
            }
        },
        Err(_) => {}
    }
    
    Ok(warp::reply::json(&json!({
        "error": "Failed to connect to node"
    })))
}

async fn send_transaction(tx_data: serde_json::Value, node_address: &str) -> Result<impl Reply, Rejection> {
    let from_wallet = tx_data["from_wallet"].as_str().unwrap_or("");
    let to_address = tx_data["to_address"].as_str().unwrap_or("");
    let amount: u64 = tx_data["amount"].as_str()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let fee: u64 = tx_data["fee"].as_str()
        .unwrap_or("1")
        .parse()
        .unwrap_or(1);
    
    if from_wallet.is_empty() || to_address.is_empty() || amount == 0 {
        return Ok(warp::reply::json(&json!({
            "success": false,
            "message": "Invalid transaction parameters",
            "error": "All fields must be filled correctly"
        })));
    }
    
    // Execute the wallet command to send the transaction
    let output = tokio::process::Command::new("cargo")
        .args(&["run", "--bin", "pali-wallet", "--", "--wallet", from_wallet, "send", "--to", to_address, "--amount", &amount.to_string(), "--fee", &fee.to_string()])
        .output()
        .await;
    
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            
            if output.status.success() {
                Ok(warp::reply::json(&json!({
                    "success": true,
                    "message": "Transaction sent successfully",
                    "details": stdout
                })))
            } else {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "message": "Failed to send transaction",
                    "error": stderr
                })))
            }
        },
        Err(e) => {
            Ok(warp::reply::json(&json!({
                "success": false,
                "message": "Failed to execute transaction command",
                "error": e.to_string()
            })))
        }
    }
}
