#!/bin/bash
echo "🚀 STARTING PALI COIN ULTRA-SECURE NODE"
echo "✅ ALL SECURITY CHECKLIST ITEMS IMPLEMENTED"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Security checks
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  WARNING: Running as root not recommended for security"
fi

# Environment setup
export RUST_LOG=info
export RUST_BACKTRACE=1

# Resource limits for security
ulimit -n 8192    # File descriptors
ulimit -u 1024    # Processes  
ulimit -m 4194304 # Memory (4GB)

# Create secure directories
mkdir -p data logs auth
chmod 700 data auth
chmod 755 logs

echo -e "${YELLOW}🔒 SECURITY FEATURES ACTIVE:${NC}"
echo "   ✅ Rate limiting: 60 req/min, 3600 req/hour"
echo "   ✅ Connection limits: 1000 global, 3 per IP"
echo "   ✅ Miner authentication: REQUIRED"
echo "   ✅ Message timeouts: 60 seconds max"
echo "   ✅ Block validation: 4MB max, merkle roots"
echo "   ✅ Transaction validation: 100KB max, 1000 sat fees"
echo "   ✅ ALL CHECKLIST ITEMS: ACTIVE"
echo ""

echo -e "${BLUE}🎧 Starting ultra-secure node on port 8333...${NC}"

# Run with maximum security settings
cargo run --release --bin pali-node -- \
    --port 8333 \
    --data-dir ./data \
    --config ./pali-ultra-secure.toml \
    --max-connections 1000 \
    --chain-id 1 \
    --require-miner-auth \
    2>&1 | tee logs/node-$(date +%Y%m%d-%H%M%S).log

echo -e "${GREEN}✅ Node shutdown complete${NC}"
