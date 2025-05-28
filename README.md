# 🚀 Palicoin - Next Generation Cryptocurrency

[![Security Status](https://img.shields.io/badge/Security-Audited-green.svg)](security/)
[![Build Status](https://img.shields.io/badge/Build-Passing-green.svg)]()
[![Version](https://img.shields.io/badge/Version-25.0.0-blue.svg)]()

Palicoin is a Bitcoin Core v25.0 fork with enhanced performance, enterprise-grade security, and optimized resource usage.

## ✨ Key Features

- ⚡ **3-minute blocks** (3x faster than Bitcoin)
- 🔒 **Enterprise security** (comprehensive audits passed)
- 💎 **21M total supply** (same scarcity model as Bitcoin)
- 🚀 **Optimized performance** (61MB memory usage)
- 🔧 **Full Bitcoin compatibility** (all RPC commands supported)

## 📊 Current Status

- **Version**: Palicoin Core v25.0
- **Security**: ✅ Production-ready (all audits passed)
- **Performance**: ✅ Highly optimized (61MB memory)
- **Economy**: ✅ Active mining generating rewards
- **Documentation**: ✅ Complete user and developer guides

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/SaifZ-Dev/pali-coin.git
cd pali-coin/bitcoin-core

# Build Palicoin
make -j$(nproc)

# Start daemon
./src/bitcoind -daemon

# Create wallet
./src/bitcoin-cli createwallet "my_wallet"

# Get new address
./src/bitcoin-cli -rpcwallet=my_wallet getnewaddress
```

## 📚 Documentation

- [User Guide](docs/user-guide/) - Getting started with Palicoin
- [Developer Guide](docs/developer-guide/) - API and development resources
- [Security Audits](docs/security/) - Comprehensive security documentation
- [Deployment Guide](docs/deployment/) - Production deployment instructions

## 🔒 Security

Palicoin has undergone comprehensive security auditing:
- ✅ Timing attack protections verified
- ✅ Buffer overflow analysis completed
- ✅ RPC authentication security confirmed
- ✅ Network security hardening applied
- ✅ Production-grade configuration implemented

[View Security Reports](security/)

## 🎯 Technical Specifications

| Parameter | Value |
|-----------|-------|
| Block Time | 3 minutes |
| Difficulty | 2x Bitcoin |
| Total Supply | 21,000,000 PALI |
| Network Port | 8535 (mainnet) |
| Address Prefix | P (legacy), pali (bech32) |
| Genesis Hash | 2424a1424062e0215c34ca2499845aca... |

## 🌐 Network Information

- **Mainnet**: Port 8535
- **Testnet**: Port 18535  
- **Regtest**: Port 18443
- **Magic Bytes**: 0xfa1c0c11

## 📈 Roadmap

- [x] **Phase 1**: Enhanced Testing - Complete
- [x] **Phase 2**: Documentation - Complete
- [x] **Phase 6**: Security Audits - Complete
- [ ] **Phase 3**: Mainnet Deployment - Ready
- [ ] **Phase 4**: Community Building - Planned
- [ ] **Phase 5**: Advanced Features - Planned

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/SaifZ-Dev/pali-coin/issues)
- **Security**: [Security Policy](SECURITY.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Built with Bitcoin Core v25.0** | **Security Audited** | **Production Ready**
