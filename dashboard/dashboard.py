#!/usr/bin/env python3
"""
Security Testing Dashboard
Real-time web dashboard for visualizing scan results
"""

try:
    from flask import Flask, render_template, jsonify, request, send_from_directory
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("[!] Flask not available - install with: pip install flask")

import json
import os
import glob
from datetime import datetime
from collections import Counter

app = Flask(__name__)

class DashboardData:
    def __init__(self, results_dir='results'):
        self.results_dir = results_dir
        self.scan_results = []
        self.stats = {
            'total_scans': 0,
            'total_vulnerabilities': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_type': {},
            'targets': [],
            'recent_scans': []
        }

    def load_results(self):
        """Load all scan results from directory"""
        self.scan_results = []
        self.stats = {
            'total_scans': 0,
            'total_vulnerabilities': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_type': {},
            'targets': [],
            'recent_scans': []
        }

        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
            return

        result_files = glob.glob(os.path.join(self.results_dir, '*.json'))

        for filepath in result_files:
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)

                    scan_info = {
                        'filename': os.path.basename(filepath),
                        'target': data.get('target', 'N/A'),
                        'timestamp': os.path.getmtime(filepath),
                        'vulnerabilities': len(data.get('vulnerabilities', [])),
                        'data': data
                    }

                    self.scan_results.append(scan_info)

                    # Update stats
                    self.stats['total_scans'] += 1

                    if data.get('target'):
                        self.stats['targets'].append(data['target'])

                    # Process vulnerabilities
                    for vuln in data.get('vulnerabilities', []):
                        self.stats['total_vulnerabilities'] += 1

                        severity = vuln.get('severity', 'info').lower()
                        if severity in self.stats['by_severity']:
                            self.stats['by_severity'][severity] += 1

                        vuln_type = vuln.get('type', 'unknown')
                        if vuln_type not in self.stats['by_type']:
                            self.stats['by_type'][vuln_type] = 0
                        self.stats['by_type'][vuln_type] += 1

            except Exception as e:
                print(f"[!] Failed to load {filepath}: {e}")

        # Sort by timestamp and get recent scans
        self.scan_results.sort(key=lambda x: x['timestamp'], reverse=True)
        self.stats['recent_scans'] = self.scan_results[:10]

        # Unique targets
        self.stats['targets'] = list(set(self.stats['targets']))

    def get_all_vulnerabilities(self):
        """Get all vulnerabilities from all scans"""
        all_vulns = []

        for scan in self.scan_results:
            for vuln in scan['data'].get('vulnerabilities', []):
                vuln['target'] = scan['target']
                vuln['scan_file'] = scan['filename']
                all_vulns.append(vuln)

        return all_vulns


dashboard_data = DashboardData()

@app.route('/')
def index():
    """Main dashboard page"""
    dashboard_data.load_results()
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """Get dashboard statistics"""
    dashboard_data.load_results()
    return jsonify(dashboard_data.stats)

@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Get all vulnerabilities"""
    dashboard_data.load_results()

    severity_filter = request.args.get('severity', 'all')
    limit = int(request.args.get('limit', 100))

    all_vulns = dashboard_data.get_all_vulnerabilities()

    # Filter by severity
    if severity_filter != 'all':
        severities = severity_filter.split(',')
        all_vulns = [v for v in all_vulns if v.get('severity', '').lower() in severities]

    # Limit results
    all_vulns = all_vulns[:limit]

    return jsonify(all_vulns)

@app.route('/api/scans')
def get_scans():
    """Get list of scans"""
    dashboard_data.load_results()

    scans = [{
        'filename': scan['filename'],
        'target': scan['target'],
        'timestamp': datetime.fromtimestamp(scan['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
        'vulnerabilities': scan['vulnerabilities']
    } for scan in dashboard_data.scan_results]

    return jsonify(scans)

@app.route('/api/scan/<filename>')
def get_scan_details(filename):
    """Get details of a specific scan"""
    dashboard_data.load_results()

    for scan in dashboard_data.scan_results:
        if scan['filename'] == filename:
            return jsonify(scan['data'])

    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/refresh', methods=['POST'])
def refresh_data():
    """Refresh dashboard data"""
    dashboard_data.load_results()
    return jsonify({'status': 'success', 'stats': dashboard_data.stats})

def run_dashboard(host='127.0.0.1', port=5000, debug=False):
    """Run the dashboard server"""
    if not FLASK_AVAILABLE:
        print("[!] Cannot run dashboard - Flask not installed")
        print("[!] Install with: pip install flask")
        return

    print(f"[*] Starting Security Testing Dashboard...")
    print(f"[*] Dashboard URL: http://{host}:{port}")
    print(f"[*] Results directory: {dashboard_data.results_dir}")
    print(f"[*] Press Ctrl+C to stop")

    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    import sys

    host = '127.0.0.1'
    port = 5000

    if len(sys.argv) > 1:
        results_dir = sys.argv[1]
        dashboard_data.results_dir = results_dir

    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    run_dashboard(host=host, port=port, debug=False)
