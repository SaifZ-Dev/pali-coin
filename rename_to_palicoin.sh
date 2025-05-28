#!/bin/bash

# Palicoin Conversion Script
# This script systematically renames everything from Bitcoin to Palicoin

echo "🚀 Converting Bitcoin Core to Palicoin..."
echo "========================================"

# Set the working directory
BITCOIN_DIR="bitcoin-core"

if [ ! -d "$BITCOIN_DIR" ]; then
    echo "❌ Error: $BITCOIN_DIR directory not found!"
    exit 1
fi

echo "📁 Working in directory: $BITCOIN_DIR"

# Backup original files before making changes
echo "💾 Creating backup..."
cp -r "$BITCOIN_DIR" "${BITCOIN_DIR}_backup"

cd "$BITCOIN_DIR"

echo "🔧 Step 1: Renaming executable outputs in Makefile..."

# Update Makefile.am to change executable names
if [ -f "Makefile.am" ]; then
    sed -i 's/bitcoind/palicoind/g' Makefile.am
    sed -i 's/bitcoin-cli/palicoin-cli/g' Makefile.am
    sed -i 's/bitcoin-tx/palicoin-tx/g' Makefile.am
    sed -i 's/bitcoin-qt/palicoin-qt/g' Makefile.am
    sed -i 's/bitcoin-wallet/palicoin-wallet/g' Makefile.am
fi

# Update configure.ac
if [ -f "configure.ac" ]; then
    echo "🔧 Step 2: Updating configure.ac..."
    sed -i 's/Bitcoin Core/Palicoin Core/g' configure.ac
    sed -i 's/bitcoin/palicoin/g' configure.ac
    sed -i 's/BITCOIN/PALICOIN/g' configure.ac
    sed -i 's/Bitcoin/Palicoin/g' configure.ac
fi

echo "🔧 Step 3: Renaming source files and updating references..."

# Find and update all .cpp and .h files
find src/ -name "*.cpp" -o -name "*.h" -o -name "*.hpp" | while read file; do
    # Update string references (keeping bitcoin as network protocol where needed)
    sed -i 's/Bitcoin Core/Palicoin Core/g' "$file"
    sed -i 's/Bitcoin/Palicoin/g' "$file"
    sed -i 's/"bitcoin"/"palicoin"/g' "$file"
    sed -i 's/bitcoind/palicoind/g' "$file"
    sed -i 's/bitcoin-cli/palicoin-cli/g' "$file"
    sed -i 's/bitcoin-tx/palicoin-tx/g' "$file"
    sed -i 's/bitcoin-qt/palicoin-qt/g' "$file"
    sed -i 's/bitcoin-wallet/palicoin-wallet/g' "$file"
    
    # Update configuration directory references
    sed -i 's/\.bitcoin/\.palicoin/g' "$file"
    sed -i 's/bitcoin\.conf/palicoin\.conf/g' "$file"
    
    # Update help text and version strings
    sed -i 's/BITCOIN_/PALICOIN_/g' "$file"
    sed -i 's/Bitcoin_/Palicoin_/g' "$file"
done

echo "🔧 Step 4: Updating build system files..."

# Update Makefile templates
find . -name "Makefile.am" | while read file; do
    sed -i 's/bitcoind/palicoind/g' "$file"
    sed -i 's/bitcoin-cli/palicoin-cli/g' "$file"
    sed -i 's/bitcoin-tx/palicoin-tx/g' "$file"
    sed -i 's/bitcoin-qt/palicoin-qt/g' "$file"
    sed -i 's/bitcoin-wallet/palicoin-wallet/g' "$file"
    sed -i 's/Bitcoin/Palicoin/g' "$file"
done

echo "🔧 Step 5: Updating documentation..."

# Update README and documentation
if [ -f "README.md" ]; then
    sed -i 's/Bitcoin Core/Palicoin Core/g' README.md
    sed -i 's/Bitcoin/Palicoin/g' README.md
    sed -i 's/bitcoin/palicoin/g' README.md
fi

# Update man pages
find doc/ -name "*.md" -o -name "*.1" | while read file; do
    sed -i 's/Bitcoin Core/Palicoin Core/g' "$file"
    sed -i 's/Bitcoin/Palicoin/g' "$file"
    sed -i 's/bitcoind/palicoind/g' "$file"
    sed -i 's/bitcoin-cli/palicoin-cli/g' "$file"
    sed -i 's/bitcoin-tx/palicoin-tx/g' "$file"
done

echo "🔧 Step 6: Updating configuration and data directory references..."

# Update default data directory
find src/ -name "*.cpp" -o -name "*.h" | xargs grep -l "\.bitcoin" | while read file; do
    sed -i 's/\.bitcoin/\.palicoin/g' "$file"
done

echo "🔧 Step 7: Updating network and protocol identifiers..."

# Update network magic bytes and identifiers (we'll customize these later)
# These changes ensure Palicoin has its own network identity

echo "🔧 Step 8: Regenerating build system..."

# Regenerate the build system with new names
if [ -f "autogen.sh" ]; then
    ./autogen.sh
fi

echo "✅ Conversion complete!"
echo ""
echo "📋 Summary of changes:"
echo "• bitcoind → palicoind"
echo "• bitcoin-cli → palicoin-cli"
echo "• bitcoin-tx → palicoin-tx"
echo "• bitcoin-qt → palicoin-qt"
echo "• bitcoin-wallet → palicoin-wallet"
echo "• .bitcoin/ → .palicoin/"
echo "• bitcoin.conf → palicoin.conf"
echo "• All 'Bitcoin' references → 'Palicoin'"
echo ""
echo "🔄 Next steps:"
echo "1. Run './configure --disable-wallet --disable-gui --disable-tests'"
echo "2. Run 'make -j2' to build Palicoin"
echo "3. Test with './src/palicoind --help'"
echo ""
echo "💾 Original files backed up to: ${BITCOIN_DIR}_backup"
echo ""
echo "🎉 Welcome to Palicoin! Your cryptocurrency is ready for customization."
