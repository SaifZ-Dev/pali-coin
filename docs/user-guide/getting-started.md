# 🚀 Getting Started with Palicoin

Welcome to Palicoin! This guide will help you get started with your first PALI transactions.

## 💎 What is Palicoin?

Palicoin (PALI) is a cryptocurrency built on Bitcoin Core v25.0 with enhanced features:
- **3-minute block times** (faster than Bitcoin)
- **2x mining difficulty** (more secure)
- **21 million total supply** (same scarcity as Bitcoin)
- **Enhanced security** (enterprise-grade protection)

## ⚡ Quick Start

### 1. Download Palicoin
```bash
git clone https://github.com/SaifZ-Dev/pali-coin.git
cd pali-coin/bitcoin-core
```

### 2. Start Palicoin
```bash
./src/bitcoind -daemon
```

### 3. Create Wallet
```bash
./src/bitcoin-cli createwallet "my_wallet"
```

### 4. Get Your Address
```bash
./src/bitcoin-cli -rpcwallet=my_wallet getnewaddress
```

### 5. Check Balance
```bash
./src/bitcoin-cli -rpcwallet=my_wallet getbalance
```

## 🎯 Next Steps
- [Set up wallet security](wallet-setup.md)
- [Start mining PALI](mining.md)
- [Send your first transaction](transactions.md)
