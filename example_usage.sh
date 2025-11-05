#!/bin/bash

# Advanced Penetration Testing Scanner - Usage Examples
# Make sure you have permission to test the target!

echo "=========================================="
echo "Advanced Penetration Testing Scanner v2.0"
echo "=========================================="
echo ""

# Example 1: Basic full scan
echo "Example 1: Basic Full Scan"
echo "python pentest_scanner.py -t https://example.com"
echo ""

# Example 2: Reconnaissance only
echo "Example 2: Reconnaissance Only"
echo "python pentest_scanner.py -t https://example.com -m recon"
echo ""

# Example 3: Vulnerability scan only
echo "Example 3: Vulnerability Scan Only"
echo "python pentest_scanner.py -t https://example.com -m scan"
echo ""

# Example 4: Full scan with custom output
echo "Example 4: Full Scan with Custom Output"
echo "python pentest_scanner.py -t https://example.com -m full -o my_security_report"
echo ""

# Example 5: Scan with Burp Suite proxy
echo "Example 5: Scan with Burp Suite Proxy"
echo "python pentest_scanner.py -t https://example.com --proxy http://127.0.0.1:8080"
echo ""

# Example 6: Verbose scan with more threads
echo "Example 6: Verbose Scan with More Threads"
echo "python pentest_scanner.py -t https://example.com --threads 20 -v"
echo ""

# Example 7: Scan with SSL verification skipped (for testing environments)
echo "Example 7: Scan with SSL Verification Skipped"
echo "python pentest_scanner.py -t https://example.com --skip-ssl"
echo ""

# Example 8: Full advanced scan
echo "Example 8: Full Advanced Scan"
echo "python pentest_scanner.py -t https://example.com \\"
echo "    --mode full \\"
echo "    --output comprehensive_report \\"
echo "    --threads 20 \\"
echo "    --timeout 15 \\"
echo "    --verbose \\"
echo "    --skip-ssl"
echo ""

echo "=========================================="
echo "Remember: Only test authorized targets!"
echo "=========================================="
