#!/bin/bash
# Plugin Testing Script
# Test all plugins for basic functionality

echo "=================================================="
echo "     PLUGIN TESTING SUITE"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TEST_TARGET="http://example.com"
TEST_API="https://api.github.com"

passed=0
failed=0

# Test function
test_plugin() {
    local plugin_name=$1
    local plugin_path=$2
    local test_args=$3

    echo -n "Testing ${plugin_name}... "

    if [ ! -f "$plugin_path" ]; then
        echo -e "${RED}FAILED${NC} - Plugin not found"
        ((failed++))
        return 1
    fi

    # Test --help or basic execution
    if python3 "$plugin_path" --help &>/dev/null || python3 "$plugin_path" $test_args &>/dev/null; then
        echo -e "${GREEN}PASSED${NC}"
        ((passed++))
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        ((failed++))
        return 1
    fi
}

# Test WebApp Scanner
echo "=== Server Testing Plugins ==="
test_plugin "webapp_scanner" \
    "server-testing/webapp_scanner/webapp_scanner.py" \
    "$TEST_TARGET"

test_plugin "nuclei_integration" \
    "server-testing/nuclei_integration/nuclei_integration.py" \
    "$TEST_TARGET"

echo ""
echo "=== API Testing Plugins ==="
test_plugin "api_exploiter" \
    "api-testing/api_exploiter/api_exploiter.py" \
    "$TEST_API"

echo ""
echo "=================================================="
echo "     TEST SUMMARY"
echo "=================================================="
echo -e "Passed: ${GREEN}${passed}${NC}"
echo -e "Failed: ${RED}${failed}${NC}"
echo ""

if [ $failed -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
