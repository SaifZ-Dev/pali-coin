# 🔧 Palicoin API Reference

Complete API reference for Palicoin developers.

## 🌐 RPC Interface

Palicoin uses Bitcoin Core's RPC interface with full compatibility.

### Wallet Operations
```bash
# Create wallet
bitcoin-cli createwallet "wallet_name"

# Get balance
bitcoin-cli -rpcwallet=wallet_name getbalance

# Generate address
bitcoin-cli -rpcwallet=wallet_name getnewaddress

# Send transaction
bitcoin-cli -rpcwallet=wallet_name sendtoaddress "address" amount
```

### Mining Operations
```bash
# Get mining info
bitcoin-cli getmininginfo

# Generate blocks (regtest)
bitcoin-cli generatetoaddress count "address"

# Get difficulty
bitcoin-cli getdifficulty
```

### Network Information
```bash
# Get blockchain info
bitcoin-cli getblockchaininfo

# Get network info
bitcoin-cli getnetworkinfo

# Get peer info
bitcoin-cli getpeerinfo
```

## 🔗 Network Parameters

- **Mainnet Port**: 8535
- **Testnet Port**: 18535
- **Regtest Port**: 18443
- **Magic Bytes**: 0xfa1c0c11
- **Genesis Hash**: 2424a1424062e0215c34ca2499845aca62035f0329be3933fde7985553275da9
