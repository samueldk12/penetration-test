#!/usr/bin/env node
/**
 * @name xss_detector
 * @description Advanced XSS detection using JavaScript
 * @category vuln_scan
 * @version 1.0.0
 * @author Penetration Test Suite
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

// XSS Payloads
const XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    'javascript:alert(1)',
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    '<video><source onerror="alert(1)">',
    '<audio src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '"><script>alert(1)</script>',
    '\'><script>alert(1)</script>',
    '</script><script>alert(1)</script>',
    '<ScRiPt>alert(1)</sCrIpT>',
    '<script>alert(String.fromCharCode(88,83,83))</script>'
];

// Parse arguments
let args = {};
try {
    args = JSON.parse(process.argv[2] || '{}');
} catch (e) {
    console.error(JSON.stringify({ success: false, error: 'Invalid arguments' }));
    process.exit(1);
}

const target = args.target;
const verbose = args.verbose || false;
const timeout = args.timeout || 10000;

if (!target) {
    console.error(JSON.stringify({ success: false, error: 'Target URL required' }));
    process.exit(1);
}

// Results storage
const results = {
    success: true,
    target: target,
    vulnerabilities: [],
    tested_payloads: 0,
    vulnerable_params: []
};

function log(message) {
    if (verbose) {
        console.error(`[XSS Detector] ${message}`);
    }
}

function makeRequest(url, callback) {
    const parsedUrl = new URL(url);
    const protocol = parsedUrl.protocol === 'https:' ? https : http;

    const options = {
        method: 'GET',
        timeout: timeout,
        headers: {
            'User-Agent': 'Mozilla/5.0 (Pentest Suite XSS Scanner)'
        }
    };

    const req = protocol.get(url, options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
            data += chunk;
        });

        res.on('end', () => {
            callback(null, {
                statusCode: res.statusCode,
                headers: res.headers,
                body: data
            });
        });
    });

    req.on('error', (err) => {
        callback(err);
    });

    req.on('timeout', () => {
        req.destroy();
        callback(new Error('Request timeout'));
    });
}

function testPayload(baseUrl, paramName, payload, callback) {
    const url = new URL(baseUrl);
    url.searchParams.set(paramName, payload);
    const testUrl = url.toString();

    log(`Testing payload on ${paramName}: ${payload}`);

    makeRequest(testUrl, (err, response) => {
        if (err) {
            log(`Error testing payload: ${err.message}`);
            callback(null, false);
            return;
        }

        // Check if payload is reflected in response
        const reflected = response.body.includes(payload);

        // Check if payload might be executed (basic detection)
        const possiblyExecutable =
            reflected &&
            !response.body.includes(`&lt;${payload}&gt;`) && // Not HTML encoded
            !response.body.includes(`\\u003c${payload}\\u003e`); // Not unicode encoded

        if (possiblyExecutable) {
            log(`✓ Potential XSS found with payload: ${payload}`);
            callback(null, true);
        } else if (reflected) {
            log(`! Payload reflected but appears encoded`);
            callback(null, false);
        } else {
            callback(null, false);
        }
    });
}

function testParameter(baseUrl, paramName) {
    return new Promise((resolve) => {
        let vulnerablePayloads = [];
        let tested = 0;

        const testNext = (index) => {
            if (index >= XSS_PAYLOADS.length) {
                resolve({
                    param: paramName,
                    vulnerable: vulnerablePayloads.length > 0,
                    payloads: vulnerablePayloads,
                    tested: tested
                });
                return;
            }

            const payload = XSS_PAYLOADS[index];
            tested++;

            testPayload(baseUrl, paramName, payload, (err, isVulnerable) => {
                if (isVulnerable) {
                    vulnerablePayloads.push(payload);
                }

                // Continue to next payload after small delay
                setTimeout(() => testNext(index + 1), 100);
            });
        };

        testNext(0);
    });
}

async function scanTarget() {
    try {
        const parsedUrl = new URL(target);

        // Extract parameters from URL
        const params = Array.from(parsedUrl.searchParams.keys());

        if (params.length === 0) {
            log('No parameters found in URL. Testing common parameter names...');

            // Test common parameter names
            const commonParams = ['q', 'search', 'query', 'id', 'page', 'url', 'redirect', 'return'];

            for (const param of commonParams) {
                results.tested_payloads++;
                const result = await testParameter(target, param);

                if (result.vulnerable) {
                    results.vulnerabilities.push({
                        type: 'xss',
                        parameter: param,
                        payloads: result.payloads,
                        severity: 'high'
                    });
                    results.vulnerable_params.push(param);
                }
            }
        } else {
            log(`Testing ${params.length} parameters found in URL`);

            for (const param of params) {
                results.tested_payloads++;
                const result = await testParameter(target, param);

                if (result.vulnerable) {
                    results.vulnerabilities.push({
                        type: 'xss',
                        parameter: param,
                        payloads: result.payloads,
                        severity: 'high'
                    });
                    results.vulnerable_params.push(param);
                }
            }
        }

        // Output results
        console.log(JSON.stringify(results, null, 2));

    } catch (error) {
        console.error(JSON.stringify({
            success: false,
            error: error.message,
            target: target
        }));
        process.exit(1);
    }
}

// Run scanner
log(`Starting XSS scan on: ${target}`);
scanTarget();
