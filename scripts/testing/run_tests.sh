#!/bin/bash
# Palicoin Testing Suite

echo "🧪 Running Palicoin Tests..."

cd ~/pali-coin/bitcoin-core

# Run unit tests
echo "Running unit tests..."
make check

# Run functional tests
echo "Running functional tests..."
test/functional/test_runner.py

# Run security tests
echo "Running security tests..."
bash ~/pali-coin/security/scripts/automated_security_tests.sh

echo "✅ All tests completed!"
