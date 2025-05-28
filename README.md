# Palicoin Core - Custom Cryptocurrency

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Version](https://img.shields.io/badge/Version-v25.0.0-blue.svg)]()

Palicoin is a custom cryptocurrency built on Bitcoin Core technology, featuring faster block times, independent network parameters, and professional-grade blockchain infrastructure.

## 🚀 Project Overview

Palicoin represents a complete blockchain implementation with custom genesis block, independent network identity, and optimized performance characteristics. Built from Bitcoin Core v25.0 with extensive customizations.

### Key Features

- **⚡ Faster Blocks**: 3-minute block times (vs Bitcoin's 10 minutes)
- **🏗️ Custom Genesis**: Unique founding block with custom message
- **🌐 Independent Network**: Own magic bytes, ports, and network identity  
- **💰 Palicoin Addresses**: Addresses start with 'P' (mainnet) and custom prefixes
- **🔧 Professional Grade**: Built on proven Bitcoin Core architecture
- **🎯 Regtest Ready**: Immediate testing and development capability

## 📊 Network Parameters

| Parameter | Value | Description |
|-----------|--------|-------------|
| **Block Time** | 3 minutes | Faster confirmation than Bitcoin |
| **Port (Mainnet)** | 8535 | Custom network port |
| **Port (Testnet)** | 18535 | Testnet port |
| **Magic Bytes** | 0xfa1c0c11 | Unique network identifier |
| **Address Prefix** | 'P' | Palicoin mainnet addresses |
| **Bech32 HRP** | "pali" | Modern address format |

## 🏗️ Genesis Block

**Hash**: `2424a1424062e0215c34ca2499845aca62035f0329be3933fde7985553275da9` (regtest)  
**Timestamp**: 1716700801 (May 26, 2025)  
**Message**: "Pali Coin Genesis - May 2025 - Building the Future of Digital Finance"  
**Merkle Root**: `2df3e6aa58417db81d93b86c5bc4f7985d2e0223bacc6c148ecf2d074f0c304b`

## 🛠️ Quick Start

### Prerequisites
- Ubuntu 20.04+ or similar Linux distribution
- C++ compiler (GCC 8+)
- Essential build tools and libraries

### Installation

```bash
# Clone the repository
git clone https://github.com/SaifZ-Dev/pali-coin.git
cd pali-coin

# Install dependencies
sudo apt update
sudo apt install build-essential git autotools-dev automake pkg-config libtool curl
sudo apt install libssl-dev libboost-all-dev libdb++-dev libminiupnpc-dev libzmq3-dev libevent-dev

# Build Palicoin
cd bitcoin-core
./autogen.sh
./configure --disable-wallet --disable-gui --disable-tests
make -j$(nproc)
```

### Testing

```bash
# Start Palicoin in regtest mode
./src/bitcoind -regtest -daemon -rpcallowip=127.0.0.1 -rpcbind=127.0.0.1 -server=1

# Check blockchain status
./src/bitcoin-cli -regtest getblockchaininfo

# Generate test blocks
./src/bitcoin-cli -regtest generatetoaddress 10 "mpjXJ9TsY6Y1jw9X1RqWzBfgQjhBWZY5T3"

# View latest block
./src/bitcoin-cli -regtest getbestblockhash
./src/bitcoin-cli -regtest getblock $(./src/bitcoin-cli -regtest getbestblockhash)
```

## 📁 Project Structure

```
palicoin/
├── bitcoin-core/           # Modified Bitcoin Core source
│   ├── src/
│   │   ├── chainparams.cpp # Custom Palicoin network parameters
│   │   └── ...
│   └── ...
├── tools/                  # Development tools
├── docs/                   # Documentation
├── scripts/               # Build and deployment scripts
└── README.md             # This file
```

## 🔧 Development

### Building with Wallet Support

```bash
# Rebuild with full wallet functionality
./configure --disable-gui --disable-tests
make clean
make -j$(nproc)

# Create wallet
./src/bitcoin-cli -regtest createwallet "mywallet"
./src/bitcoin-cli -regtest getnewaddress
```

### Network Operations

```bash
# Start mainnet node (when ready for production)
./src/bitcoind -daemon

# Connect to testnet
./src/bitcoind -testnet -daemon

# Mining and transactions
./src/bitcoin-cli generatetoaddress [blocks] [address]
./src/bitcoin-cli sendtoaddress [address] [amount]
```

## 🌐 Network Information

### Mainnet Configuration
- **Port**: 8535
- **RPC Port**: 8536
- **Magic Bytes**: 0xfa1c0c11

### Testnet Configuration  
- **Port**: 18535
- **RPC Port**: 18536
- **Magic Bytes**: 0x0b110907

### Regtest Configuration
- **Port**: 18444
