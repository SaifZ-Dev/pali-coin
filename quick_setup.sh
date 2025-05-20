#!/bin/bash

# Create Cargo.toml
cat > Cargo.toml << 'CARGO_EOF'
[package]
name = "pali-coin"
version = "0.1.0"
edition = "2021"

[dependencies]
sha2 = "0.10"
ed25519-dalek = "2.0"
rand = "0.8"
bellman = "0.14"
bls12_381 = "0.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
bincode = "1.3"
tokio = { version = "1.0", features = ["full"] }
reqwest = { version = "0.11", features = ["json"] }
rocksdb = "0.21"
clap = { version = "4.0", features = ["derive"] }
chrono = { version = "0.4", features = ["serde"] }
hex = "0.4"
log = "0.4"
env_logger = "0.10"

[[bin]]
name = "pali-node"
path = "src/main.rs"

[[bin]]
name = "pali-miner" 
path = "src/miner.rs"

[[bin]]
name = "pali-wallet"
path = "src/wallet.rs"
CARGO_EOF

echo "Created Cargo.toml"
echo "Now you need to create the src files manually from the artifacts provided"
