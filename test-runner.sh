#!/bin/bash

# Pali Coin Test Runner
# This script provides a convenient way to run different test groups

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print header
echo -e "${BLUE}=================================${NC}"
echo -e "${BLUE}    Pali Coin Test Runner    ${NC}"
echo -e "${BLUE}=================================${NC}"

# Clean test directories if they exist
clean_test_dirs() {
    echo -e "${YELLOW}Cleaning test directories...${NC}"
    if [ -d "test_data" ]; then
        rm -rf test_data
    fi
    if [ -d "blockchain_test_data" ]; then
        rm -rf blockchain_test_data
    fi
    if [ -d "wallet_test_data" ]; then
        rm -rf wallet_test_data
    fi
    mkdir -p test_data
    mkdir -p blockchain_test_data
    mkdir -p wallet_test_data
    echo -e "${GREEN}Test directories cleaned!${NC}"
}

# Function to run a specific test group
run_test() {
    local test_name=$1
    local nocapture=$2
    
    echo -e "${YELLOW}Running tests for: ${test_name}${NC}"
    
    if [ "$nocapture" = true ]; then
        cargo test $test_name -- --nocapture
    else
        cargo test $test_name
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Tests for ${test_name} passed!${NC}"
        return 0
    else
        echo -e "${RED}✗ Tests for ${test_name} failed!${NC}"
        return 1
    fi
}

# Display usage information
show_help() {
    echo -e "Usage: $0 [options] [test_name]"
    echo -e "Options:"
    echo -e "  -a, --all           Run all tests"
    echo -e "  -w, --wallet        Run wallet tests"
    echo -e "  -b, --blockchain    Run blockchain tests"
    echo -e "  -t, --transaction   Run transaction tests"
    echo -e "  -s, --secure        Run secure channel tests"
    echo -e "  -i, --integration   Run integration tests"
    echo -e "  -c, --clean         Clean test directories before running tests"
    echo -e "  -v, --verbose       Show test output"
    echo -e "  -h, --help          Show this help message"
    echo -e "\nExample: $0 --wallet --verbose"
}

# Default settings
CLEAN=false
VERBOSE=false
ALL_TESTS=false
WALLET_TESTS=false
BLOCKCHAIN_TESTS=false
TRANSACTION_TESTS=false
SECURE_CHANNEL_TESTS=false
INTEGRATION_TESTS=false
CUSTOM_TEST=""

# Check for no arguments
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--all)
            ALL_TESTS=true
            shift
            ;;
        -w|--wallet)
            WALLET_TESTS=true
            shift
            ;;
        -b|--blockchain)
            BLOCKCHAIN_TESTS=true
            shift
            ;;
        -t|--transaction)
            TRANSACTION_TESTS=true
            shift
            ;;
        -s|--secure)
            SECURE_CHANNEL_TESTS=true
            shift
            ;;
        -i|--integration)
            INTEGRATION_TESTS=true
            shift
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            CUSTOM_TEST="$1"
            shift
            ;;
    esac
done

# Clean test directories if requested
if [ "$CLEAN" = true ]; then
    clean_test_dirs
fi

# Array to collect test results
declare -a RESULTS
declare -a FAILED_TESTS

# Run tests based on options
if [ "$ALL_TESTS" = true ]; then
    run_test "" "$VERBOSE"
    RESULTS+=($?)
elif [ ! -z "$CUSTOM_TEST" ]; then
    run_test "$CUSTOM_TEST" "$VERBOSE"
    RESULTS+=($?)
    if [ ${RESULTS[-1]} -ne 0 ]; then
        FAILED_TESTS+=("$CUSTOM_TEST")
    fi
else
    if [ "$WALLET_TESTS" = true ]; then
        run_test "wallet_test" "$VERBOSE"
        RESULTS+=($?)
        if [ ${RESULTS[-1]} -ne 0 ]; then
            FAILED_TESTS+=("wallet_test")
        fi
    fi
    
    if [ "$BLOCKCHAIN_TESTS" = true ]; then
        run_test "blockchain_test" "$VERBOSE"
        RESULTS+=($?)
        if [ ${RESULTS[-1]} -ne 0 ]; then
            FAILED_TESTS+=("blockchain_test")
        fi
    fi
    
    if [ "$TRANSACTION_TESTS" = true ]; then
        run_test "transaction_test" "$VERBOSE"
        RESULTS+=($?)
        if [ ${RESULTS[-1]} -ne 0 ]; then
            FAILED_TESTS+=("transaction_test")
        fi
    fi
    
    if [ "$SECURE_CHANNEL_TESTS" = true ]; then
        run_test "secure_channel_test" "$VERBOSE"
        RESULTS+=($?)
        if [ ${RESULTS[-1]} -ne 0 ]; then
            FAILED_TESTS+=("secure_channel_test")
        fi
    fi
    
    if [ "$INTEGRATION_TESTS" = true ]; then
        run_test "integration_test" "$VERBOSE"
        RESULTS+=($?)
        if [ ${RESULTS[-1]} -ne 0 ]; then
            FAILED_TESTS+=("integration_test")
        fi
    fi
fi

# Display test summary
echo -e "${BLUE}=================================${NC}"
echo -e "${BLUE}         Test Summary         ${NC}"
echo -e "${BLUE}=================================${NC}"

SUCCESS=true
for result in "${RESULTS[@]}"; do
    if [ $result -ne 0 ]; then
        SUCCESS=false
        break
    fi
done

if [ "$SUCCESS" = true ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed:${NC}"
    for test in "${FAILED_TESTS[@]}"; do
        echo -e "${RED}  - ${test}${NC}"
    done
fi

# Run specific test file with focus on performance
run_performance_test() {
    echo -e "${YELLOW}Running performance tests...${NC}"
    
    # Compile in release mode for more accurate performance
    RUSTFLAGS="-C target-cpu=native" cargo test --release $1 -- --nocapture
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Performance tests passed!${NC}"
    else
        echo -e "${RED}✗ Performance tests failed!${NC}"
    fi
}

# Function to check code coverage
check_coverage() {
    echo -e "${YELLOW}Checking code coverage...${NC}"
    
    # Check if cargo-tarpaulin is installed
    if ! command -v cargo-tarpaulin &> /dev/null; then
        echo -e "${RED}cargo-tarpaulin is not installed. Install it with:${NC}"
        echo -e "${BLUE}cargo install cargo-tarpaulin${NC}"
        return 1
    fi
    
    cargo tarpaulin --out Html
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Coverage report generated!${NC}"
        echo -e "${BLUE}Open tarpaulin-report.html to view the coverage report.${NC}"
    else
        echo -e "${RED}✗ Failed to generate coverage report!${NC}"
    fi
}

# Special options for developers (uncomment as needed)
# run_performance_test "bench"
# check_coverage

exit 0
