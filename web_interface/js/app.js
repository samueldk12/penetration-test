// API Base URL
const API_BASE = '';
const socket = io();

// State
const state = {
    targets: new Map(),
    scans: new Map(),
    plugins: [],
    activeView: 'dashboard'
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    setupEventListeners();
    setupWebSocket();
});

function initializeApp() {
    loadStats();
    loadPlugins();
    loadScans();
}

// Navigation
function setupEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const view = item.dataset.view;
            switchView(view);
        });
    });

    // Modals
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => closeModal(btn.closest('.modal')));
    });

    // New Scan
    document.getElementById('new-scan-btn').addEventListener('click', () => openModal('new-scan-modal'));
    document.getElementById('start-scan-btn').addEventListener('click', startScan);

    // Notes
    document.getElementById('add-note-btn')?.addEventListener('click', () => openModal('note-modal'));
    document.getElementById('save-note-btn')?.addEventListener('click', saveNote);

    // API Keys
    document.getElementById('add-key-btn')?.addEventListener('click', () => openModal('key-modal'));
    document.getElementById('save-key-btn')?.addEventListener('click', saveAPIKey);

    // Plugins
    document.getElementById('install-plugin-btn')?.addEventListener('click', () => openModal('plugin-install-modal'));
    document.getElementById('install-plugin-confirm-btn')?.addEventListener('click', installPlugin);

    // Report
    document.getElementById('generate-report-btn')?.addEventListener('click', generateReport);
}

function switchView(viewName) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(viewName + '-view').classList.add('active');

    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    document.querySelector('[data-view="' + viewName + '"]').classList.add('active');

    document.querySelector('.header-title').textContent = viewName.charAt(0).toUpperCase() + viewName.slice(1);

    // Load view-specific data
    if (viewName === 'plugins') loadPlugins();
    if (viewName === 'notes') loadNotes();
    if (viewName === 'api-keys') loadAPIKeys();
    if (viewName === 'config') loadConfig();
    if (viewName === 'reports') loadReports();
}

// Modal Management
function openModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

function closeModal(modal) {
    modal.classList.remove('active');
}

// API Calls
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method,
        headers: {'Content-Type': 'application/json'}
    };
    if (data) options.body = JSON.stringify(data);

    try {
        const response = await fetch(API_BASE + endpoint, options);
        return await response.json();
    } catch (error) {
        showToast('API Error: ' + error.message, 'error');
        throw error;
    }
}

// Stats
async function loadStats() {
    try {
        const plugins = await apiCall('/api/plugins');
        document.getElementById('stat-plugins').textContent = plugins.count.total;

        const scans = await apiCall('/api/scans');
        const completed = scans.scans.filter(s => s.status === 'completed').length;
        document.getElementById('stat-completed').textContent = completed;
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Scans
async function startScan() {
    const target = document.getElementById('scan-target').value;
    const type = document.getElementById('scan-type').value;

    if (!target) {
        showToast('Target is required', 'error');
        return;
    }

    const scanData = {target};

    if (type === 'category') {
        const categories = Array.from(document.getElementById('scan-categories').selectedOptions).map(o => o.value);
        scanData.categories = categories;
    } else if (type === 'specific') {
        const plugins = Array.from(document.getElementById('scan-plugins').selectedOptions).map(o => o.value);
        scanData.plugins = plugins;
    }

    try {
        const result = await apiCall('/api/scans', 'POST', scanData);
        showToast('Scan started: ' + result.scan_id, 'success');
        closeModal(document.getElementById('new-scan-modal'));
        loadScans();
    } catch (error) {
        showToast('Failed to start scan', 'error');
    }
}

async function loadScans() {
    try {
        const data = await apiCall('/api/scans');
        const listEl = document.getElementById('scans-list');
        if (!listEl) return;

        listEl.innerHTML = '';

        data.scans.forEach(scan => {
            const scanEl = document.createElement('div');
            scanEl.className = 'card';
            scanEl.innerHTML = '<div class="card-body"><h4>' + scan.target + '</h4><p>Status: ' + scan.status + ' | Progress: ' + scan.progress + '%</p><p>Started: ' + scan.started_at + '</p></div>';
            listEl.appendChild(scanEl);
        });
    } catch (error) {
        console.error('Failed to load scans:', error);
    }
}

// Plugins
async function loadPlugins() {
    try {
        const data = await apiCall('/api/plugins');
        state.plugins = data.plugins;
        const gridEl = document.getElementById('plugins-grid');
        if (!gridEl) return;

        gridEl.innerHTML = '';

        data.plugins.forEach(plugin => {
            const pluginEl = document.createElement('div');
            pluginEl.className = 'card';
            pluginEl.innerHTML = '<div class="card-body"><h4>' + plugin.name + ' <span style="font-size:0.8rem;color:#a0aec0">(' + plugin.type + ')</span></h4><p>' + plugin.description + '</p><p>Category: ' + plugin.category + ' | Version: ' + plugin.version + '</p></div>';
            gridEl.appendChild(pluginEl);
        });

        // Populate scan modal plugin select
        const selectEl = document.getElementById('scan-plugins');
        if (selectEl) {
            selectEl.innerHTML = '';
            data.plugins.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.name;
                opt.textContent = p.name + ' (' + p.type + ')';
                selectEl.appendChild(opt);
            });
        }
    } catch (error) {
        console.error('Failed to load plugins:', error);
    }
}

async function installPlugin() {
    const url = document.getElementById('plugin-url').value;
    const type = document.getElementById('plugin-type').value;
    const force = document.getElementById('plugin-force').checked;

    if (!url) {
        showToast('URL is required', 'error');
        return;
    }

    try {
        await apiCall('/api/plugins/install', 'POST', {url, type, force});
        showToast('Plugin installed successfully', 'success');
        closeModal(document.getElementById('plugin-install-modal'));
        loadPlugins();
    } catch (error) {
        showToast('Failed to install plugin', 'error');
    }
}

// Notes
async function loadNotes() {
    try {
        const data = await apiCall('/api/notes');
        const listEl = document.getElementById('notes-list');
        if (!listEl) return;

        listEl.innerHTML = '';

        data.notes.forEach(note => {
            const noteEl = document.createElement('div');
            noteEl.className = 'card';
            noteEl.innerHTML = '<div class="card-body"><h4>' + note.target + '</h4><p>' + note.note + '</p><small>Created: ' + note.created_at + '</small></div>';
            listEl.appendChild(noteEl);
        });
    } catch (error) {
        console.error('Failed to load notes:', error);
    }
}

async function saveNote() {
    const target = document.getElementById('note-target').value;
    const note = document.getElementById('note-content').value;

    if (!target || !note) {
        showToast('Target and note are required', 'error');
        return;
    }

    try {
        await apiCall('/api/notes', 'POST', {target, note});
        showToast('Note saved', 'success');
        closeModal(document.getElementById('note-modal'));
        loadNotes();
    } catch (error) {
        showToast('Failed to save note', 'error');
    }
}

// API Keys
async function loadAPIKeys() {
    try {
        const data = await apiCall('/api/keys');
        const listEl = document.getElementById('keys-list');
        if (!listEl) return;

        listEl.innerHTML = '';

        data.keys.forEach(key => {
            const keyEl = document.createElement('div');
            keyEl.className = 'card';
            keyEl.innerHTML = '<div class="card-body"><h4>' + key.service + '</h4><p>' + key.key + '</p><p>' + (key.description || '') + '</p></div>';
            listEl.appendChild(keyEl);
        });
    } catch (error) {
        console.error('Failed to load keys:', error);
    }
}

async function saveAPIKey() {
    const service = document.getElementById('key-service').value;
    const key = document.getElementById('key-value').value;
    const description = document.getElementById('key-description').value;

    if (!service || !key) {
        showToast('Service and key are required', 'error');
        return;
    }

    try {
        await apiCall('/api/keys', 'POST', {service, key, description});
        showToast('API Key saved', 'success');
        closeModal(document.getElementById('key-modal'));
        loadAPIKeys();
    } catch (error) {
        showToast('Failed to save key', 'error');
    }
}

// Reports
async function loadReports() {
    try {
        const data = await apiCall('/api/reports');
        const contentEl = document.getElementById('report-content');
        if (contentEl) {
            contentEl.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        }
    } catch (error) {
        console.error('Failed to load reports:', error);
    }
}

async function generateReport() {
    const severity = document.getElementById('report-severity').value;
    try {
        const data = await apiCall('/api/reports/generate', 'POST', {severity, format: 'json'});
        showToast('Report generated', 'success');
        document.getElementById('report-content').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
    } catch (error) {
        showToast('Failed to generate report', 'error');
    }
}

// Config
async function loadConfig() {
    try {
        const config = await apiCall('/api/config');
        const editorEl = document.getElementById('config-editor');
        if (editorEl) {
            editorEl.innerHTML = '<pre>' + JSON.stringify(config, null, 2) + '</pre>';
        }
    } catch (error) {
        console.error('Failed to load config:', error);
    }
}

// WebSocket
function setupWebSocket() {
    socket.on('connect', () => {
        document.getElementById('connection-status').innerHTML = '<i class="fas fa-circle"></i><span>Connected</span>';
    });

    socket.on('disconnect', () => {
        document.getElementById('connection-status').innerHTML = '<i class="fas fa-circle"></i><span>Disconnected</span>';
    });

    socket.on('scan_status', (data) => {
        showToast('Scan ' + data.scan_id + ': ' + data.message, 'info');
        loadScans();
    });
}

// Toast
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    document.getElementById('toast-container').appendChild(toast);

    setTimeout(() => toast.remove(), 5000);
}
