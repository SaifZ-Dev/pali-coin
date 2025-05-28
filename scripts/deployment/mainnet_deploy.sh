#!/bin/bash
# Palicoin Mainnet Deployment Script - Path Fixed

set -e

echo "🚀 Deploying Palicoin to Mainnet..."

# Check if we're in the right directory
PALI_DIR="$HOME/pali-coin"
if [ ! -d "$PALI_DIR/bitcoin-core" ]; then
    echo "❌ Palicoin directory not found. Please run from: $PALI_DIR"
    exit 1
fi

cd "$PALI_DIR/bitcoin-core"

# Check if bitcoind exists
if [ ! -f "src/bitcoind" ]; then
    echo "❌ Palicoin not built. Please run 'make' first."
    exit 1
fi

# Stop any existing daemon
echo "🛑 Stopping any existing daemon..."
./src/bitcoin-cli stop 2>/dev/null || echo "No daemon running"
sleep 3

# Create mainnet data directory
echo "📁 Creating mainnet data directory..."
PALICOIN_DIR="$HOME/.palicoin"
mkdir -p "$PALICOIN_DIR"

# Create mainnet configuration
echo "📝 Creating mainnet configuration..."
cat > "$PALICOIN_DIR/palicoin.conf" << 'EOF'
# Palicoin Mainnet Configuration
testnet=0
regtest=0
server=1
listen=1
port=8535
rpcport=8536
bind=0.0.0.0:8535
rpcbind=127.0.0.1:8536
rpcallowip=127.0.0.1
maxconnections=125
dbcache=450
disablewallet=0
printtoconsole=0
debug=0
shrinkdebugfile=1
EOF

echo "✅ Configuration created at: $PALICOIN_DIR/palicoin.conf"

# Start Palicoin mainnet daemon
echo "🚀 Starting Palicoin mainnet daemon..."
./src/bitcoind -datadir="$PALICOIN_DIR" -daemon

# Wait for daemon to start
echo "⏳ Waiting for daemon to start..."
sleep 5

# Check if daemon is running
if ./src/bitcoin-cli -datadir="$PALICOIN_DIR" getblockchaininfo >/dev/null 2>&1; then
    echo "✅ Palicoin mainnet daemon started successfully!"
    echo ""
    echo "📊 Network Information:"
    ./src/bitcoin-cli -datadir="$PALICOIN_DIR" getblockchaininfo | head -10
    echo ""
    echo "🎯 Mainnet Commands:"
    echo "  Create wallet: ./src/bitcoin-cli -datadir=\"$PALICOIN_DIR\" createwallet \"mainnet_wallet\""
    echo "  Check status:  ./src/bitcoin-cli -datadir=\"$PALICOIN_DIR\" getblockchaininfo"
    echo "  Stop daemon:   ./src/bitcoin-cli -datadir=\"$PALICOIN_DIR\" stop"
    echo ""
    echo "🌐 Your Palicoin mainnet node is running on:"
    echo "  - Network Port: 8535"
    echo "  - RPC Port: 8536"
    echo "  - Data Directory: $PALICOIN_DIR"
else
    echo "❌ Failed to start Palicoin daemon"
    echo "💡 Check the error above or look at debug.log"
    exit 1
fi

echo ""
echo "🎉 PALICOIN MAINNET DEPLOYMENT COMPLETE!"
echo "🚀 Your cryptocurrency is now live on the mainnet!"
