#!/usr/bin/env python3
"""
Web Server for Penetration Test Suite
Provides REST API and Web Interface
"""

import os
import sys
import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
from flask_socketio import SocketIO, emit

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent / 'tools'))

from plugin_manager import PluginManager
from plugin_orchestrator import PluginOrchestrator
from advanced_reporter import AdvancedReporter
from config_manager import ConfigManager
from osint_module import OSINTModule
from js_plugin_runner import JSPluginRunner
from go_plugin_runner import GoPluginRunner
from plugin_installer import PluginInstaller
from notification_system import NotificationSystem

app = Flask(__name__, static_folder='web_interface', static_url_path='')
app.config['SECRET_KEY'] = os.urandom(24)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
active_scans = {}
scan_lock = threading.Lock()

# Database for notes and API keys
NOTES_DB = 'web_data.db'


def init_web_database():
    """Initialize database for web-specific data"""
    conn = sqlite3.connect(NOTES_DB)
    c = conn.cursor()

    # Notes table
    c.execute('''CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        note TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # API keys table (encrypted in production)
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL UNIQUE,
        key TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Environment variables table
    c.execute('''CREATE TABLE IF NOT EXISTS env_vars (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        value TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()
    conn.close()


# Routes

@app.route('/')
def index():
    """Serve the main web interface"""
    return send_from_directory('web_interface', 'index.html')


@app.route('/api/status')
def api_status():
    """API health check"""
    return jsonify({
        'status': 'online',
        'version': '2.0.0',
        'timestamp': datetime.now().isoformat()
    })


# Scan API

@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Get all active and completed scans"""
    with scan_lock:
        scans_list = []
        for scan_id, scan_data in active_scans.items():
            scans_list.append({
                'id': scan_id,
                'target': scan_data['target'],
                'status': scan_data['status'],
                'progress': scan_data.get('progress', 0),
                'started_at': scan_data.get('started_at'),
                'completed_at': scan_data.get('completed_at'),
                'plugins': scan_data.get('plugins', [])
            })

    return jsonify({'scans': scans_list})


@app.route('/api/scans/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get specific scan details"""
    with scan_lock:
        scan_data = active_scans.get(scan_id)

    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404

    return jsonify(scan_data)


@app.route('/api/scans', methods=['POST'])
def create_scan():
    """Create and start a new scan"""
    data = request.json

    if not data.get('target'):
        return jsonify({'error': 'Target is required'}), 400

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    scan_data = {
        'id': scan_id,
        'target': data['target'],
        'status': 'queued',
        'progress': 0,
        'plugins': data.get('plugins', []),
        'categories': data.get('categories', []),
        'options': data.get('options', {}),
        'started_at': datetime.now().isoformat(),
        'results': {}
    }

    with scan_lock:
        active_scans[scan_id] = scan_data

    # Start scan in background thread
    thread = threading.Thread(target=run_scan, args=(scan_id,))
    thread.daemon = True
    thread.start()

    return jsonify({'scan_id': scan_id, 'status': 'queued'}), 201


def run_scan(scan_id: str):
    """Run scan in background"""
    try:
        with scan_lock:
            scan_data = active_scans[scan_id]
            scan_data['status'] = 'running'

        # Emit status update via WebSocket
        socketio.emit('scan_status', {
            'scan_id': scan_id,
            'status': 'running',
            'message': 'Scan started'
        })

        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load_config()

        # Initialize orchestrator
        orchestrator = PluginOrchestrator(config, verbose=True)

        target = scan_data['target']
        plugins = scan_data.get('plugins', [])
        categories = scan_data.get('categories', [])

        # Run scan
        if plugins:
            results = orchestrator.run_plugins(target, plugin_names=plugins)
        elif categories:
            results = orchestrator.run_by_category(target, categories)
        else:
            results = orchestrator.run_all_plugins(target)

        # Update scan data
        with scan_lock:
            scan_data['status'] = 'completed'
            scan_data['progress'] = 100
            scan_data['completed_at'] = datetime.now().isoformat()
            scan_data['results'] = results
            scan_data['summary'] = results.get('summary', {})

        # Emit completion
        socketio.emit('scan_status', {
            'scan_id': scan_id,
            'status': 'completed',
            'message': 'Scan completed successfully',
            'summary': results.get('summary', {})
        })

    except Exception as e:
        with scan_lock:
            scan_data['status'] = 'failed'
            scan_data['error'] = str(e)
            scan_data['completed_at'] = datetime.now().isoformat()

        socketio.emit('scan_status', {
            'scan_id': scan_id,
            'status': 'failed',
            'message': f'Scan failed: {str(e)}'
        })


# OSINT API

@app.route('/api/osint', methods=['POST'])
def run_osint():
    """Run OSINT investigation"""
    data = request.json
    target = data.get('target')
    deep = data.get('deep', False)

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    try:
        osint = OSINTModule(verbose=True)
        results = osint.investigate(target, deep=deep)

        return jsonify({
            'success': True,
            'target': target,
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Plugin API

@app.route('/api/plugins', methods=['GET'])
def get_plugins():
    """Get all available plugins"""
    try:
        # Python plugins
        plugin_manager = PluginManager()
        plugin_manager.discover_plugins()

        python_plugins = []
        for name, plugin in plugin_manager.plugins.items():
            python_plugins.append({
                'name': name,
                'description': plugin.description,
                'category': plugin.category,
                'version': plugin.version,
                'type': 'python'
            })

        # JS plugins
        js_runner = JSPluginRunner()
        js_plugins = []
        if js_runner.is_available():
            for plugin in js_runner.discover_js_plugins():
                js_plugins.append({
                    'name': plugin['name'],
                    'description': plugin['description'],
                    'category': plugin['category'],
                    'version': plugin['version'],
                    'type': 'javascript'
                })

        # Go plugins
        go_runner = GoPluginRunner()
        go_plugins = []
        if go_runner.is_available():
            for plugin in go_runner.discover_go_plugins():
                go_plugins.append({
                    'name': plugin['name'],
                    'description': plugin['description'],
                    'category': plugin['category'],
                    'version': plugin['version'],
                    'type': 'go',
                    'compiled': plugin.get('compiled', False)
                })

        return jsonify({
            'plugins': python_plugins + js_plugins + go_plugins,
            'count': {
                'python': len(python_plugins),
                'javascript': len(js_plugins),
                'go': len(go_plugins),
                'total': len(python_plugins) + len(js_plugins) + len(go_plugins)
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/plugins/install', methods=['POST'])
def install_plugin():
    """Install plugin from URL"""
    data = request.json
    url = data.get('url')
    plugin_type = data.get('type')
    force = data.get('force', False)

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        installer = PluginInstaller()
        result = installer.install_from_url(url, plugin_type=plugin_type, force=force)

        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# Report API

@app.route('/api/reports', methods=['GET'])
def get_reports():
    """Get available reports"""
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()

        reporter = AdvancedReporter(config)

        # Get filters from query params
        domain = request.args.get('domain')
        severity = request.args.get('severity', '').split(',') if request.args.get('severity') else None
        vuln_type = request.args.get('vuln_type', '').split(',') if request.args.get('vuln_type') else None
        from_date = request.args.get('from')
        to_date = request.args.get('to')

        # Generate report data
        report_data = reporter.generate_comprehensive_report(
            domain=domain,
            severity_filter=severity,
            vuln_type_filter=vuln_type,
            from_date=from_date,
            to_date=to_date
        )

        reporter.close()

        return jsonify(report_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """Generate report in specific format"""
    data = request.json
    format_type = data.get('format', 'json')

    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()

        reporter = AdvancedReporter(config)

        # Get filters
        domain = data.get('domain')
        severity = data.get('severity')
        vuln_type = data.get('vuln_type')

        report_data = reporter.generate_comprehensive_report(
            domain=domain,
            severity_filter=severity,
            vuln_type_filter=vuln_type
        )

        reporter.close()

        if format_type == 'json':
            return jsonify(report_data)
        elif format_type == 'html':
            # Generate HTML report
            html = reporter.format_html_report(report_data)
            return Response(html, mimetype='text/html')
        else:
            return jsonify({'error': 'Unsupported format'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Notes API

@app.route('/api/notes', methods=['GET'])
def get_notes():
    """Get all notes or notes for specific target"""
    target = request.args.get('target')

    conn = sqlite3.connect(NOTES_DB)
    c = conn.cursor()

    if target:
        c.execute('SELECT * FROM notes WHERE target = ? ORDER BY updated_at DESC', (target,))
    else:
        c.execute('SELECT * FROM notes ORDER BY updated_at DESC')

    notes = []
    for row in c.fetchall():
        notes.append({
            'id': row[0],
            'target': row[1],
            'note': row[2],
            'created_at': row[3],
            'updated_at': row[4]
        })

    conn.close()

    return jsonify({'notes': notes})


@app.route('/api/notes', methods=['POST'])
def create_note():
    """Create a new note"""
    data = request.json
    target = data.get('target')
    note = data.get('note')

    if not target or not note:
        return jsonify({'error': 'Target and note are required'}), 400

    conn = sqlite3.connect(NOTES_DB)
    c = conn.cursor()

    c.execute('INSERT INTO notes (target, note) VALUES (?, ?)', (target, note))
    note_id = c.lastrowid

    conn.commit()
    conn.close()

    return jsonify({'id': note_id, 'success': True}), 201


@app.route('/api/notes/<int:note_id>', methods=['PUT'])
def update_note(note_id):
    """Update a note"""
    data = request.json
    note = data.get('note')

    if not note:
        return jsonify({'error': 'Note content is required'}), 400

    conn = sqlite3.connect(NOTES_DB)
    c = conn.cursor()

    c.execute('UPDATE notes SET note = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (note, note_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True})


@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
def delete_note(note_id):
    """Delete a note"""
    conn = sqlite3.connect(NOTES_DB)
    c = conn.cursor()

    c.execute('DELETE FROM notes WHERE id = ?', (note_id,))
    conn.commit()
    conn.close()

    return jsonify({'success': True})


# API Keys API

@app.route('/api/keys', methods=['GET'])
def get_api_keys():
    """Get all API keys (masked)"""
    conn = sqlite3.connect(NOTES_DB)
    c = conn.cursor()

    c.execute('SELECT id, service, key, description, created_at FROM api_keys')

    keys = []
    for row in c.fetchall():
        # Mask the key
        key_value = row[2]
        masked_key = key_value[:4] + '*' * (len(key_value) - 8) + key_value[-4:] if len(key_value) > 8 else '****'

        keys.append({
            'id': row[0],
            'service': row[1],
            'key': masked_key,
            'description': row[3],
            'created_at': row[4]
        })

    conn.close()

    return jsonify({'keys': keys})


@app.route('/api/keys', methods=['POST'])
def create_api_key():
    """Create or update an API key"""
    data = request.json
    service = data.get('service')
    key = data.get('key')
    description = data.get('description', '')

    if not service or not key:
        return jsonify({'error': 'Service and key are required'}), 400

    conn = sqlite3.connect(NOTES_DB)
    c = conn.cursor()

    # Upsert
    c.execute('''INSERT INTO api_keys (service, key, description)
                 VALUES (?, ?, ?)
                 ON CONFLICT(service) DO UPDATE SET
                 key=excluded.key,
                 description=excluded.description,
                 updated_at=CURRENT_TIMESTAMP''',
              (service, key, description))

    conn.commit()
    conn.close()

    return jsonify({'success': True}), 201


@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
def delete_api_key(key_id):
    """Delete an API key"""
    conn = sqlite3.connect(NOTES_DB)
    c = conn.cursor()

    c.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()

    return jsonify({'success': True})


# Configuration API

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()

        return jsonify(config)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['PUT'])
def update_config():
    """Update configuration"""
    data = request.json

    try:
        config_manager = ConfigManager()
        config_manager.save_config(data)

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# WebSocket Events

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    emit('connected', {'message': 'Connected to server'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnect"""
    print('Client disconnected')


@socketio.on('subscribe_scan')
def handle_subscribe_scan(data):
    """Subscribe to scan updates"""
    scan_id = data.get('scan_id')
    print(f'Client subscribed to scan: {scan_id}')
    # Join room for this scan
    # room = f'scan_{scan_id}'
    # join_room(room)


def start_server(host='127.0.0.1', port=5000, debug=False):
    """Start the web server"""
    init_web_database()
    print(f"""
╔══════════════════════════════════════════════════════════╗
║     Penetration Test Suite - Web Interface              ║
║══════════════════════════════════════════════════════════║
║  Server running at: http://{host}:{port}               ║
║══════════════════════════════════════════════════════════║
║  Press Ctrl+C to stop                                    ║
╚══════════════════════════════════════════════════════════╝
    """)

    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    start_server(debug=True)
