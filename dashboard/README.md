# Security Testing Dashboard

Real-time web dashboard for visualizing security scan results.

## Features

✅ Real-time vulnerability monitoring
✅ Interactive statistics and charts
✅ Severity-based filtering
✅ Recent scans overview
✅ Auto-refresh every 30 seconds
✅ Dark theme optimized for security operations
✅ RESTful API for integration
✅ Responsive design

## Installation

```bash
# Install Flask
pip install flask

# Or install all dependencies
pip install -r requirements.txt
```

## Usage

### Start Dashboard

```bash
# Default (results from 'results/' directory on port 5000)
python3 dashboard.py

# Custom results directory
python3 dashboard.py /path/to/scan/results

# Custom port
python3 dashboard.py /path/to/scan/results 8080
```

### Access Dashboard

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

## Dashboard Sections

### 1. Statistics Overview

Real-time statistics showing:
- Total vulnerabilities found
- Number of scans completed
- Targets scanned
- Critical issues count

### 2. Severity Breakdown

Visual breakdown of vulnerabilities by severity:
- Critical
- High
- Medium
- Low
- Info

### 3. Vulnerabilities Table

Detailed table of all vulnerabilities with:
- Severity badges
- Vulnerability type
- Target URL
- Description
- Filtering by severity

### 4. Recent Scans

List of recent scans showing:
- Filename
- Target
- Timestamp
- Vulnerability count

## API Endpoints

The dashboard provides RESTful API endpoints for integration:

### GET /api/stats

Get dashboard statistics:

```bash
curl http://localhost:5000/api/stats
```

Response:
```json
{
  "total_scans": 5,
  "total_vulnerabilities": 42,
  "by_severity": {
    "critical": 3,
    "high": 8,
    "medium": 15,
    "low": 12,
    "info": 4
  },
  "targets": ["https://example.com", "https://api.example.com"],
  "recent_scans": [...]
}
```

### GET /api/vulnerabilities

Get all vulnerabilities:

```bash
# All vulnerabilities
curl http://localhost:5000/api/vulnerabilities

# Filter by severity
curl http://localhost:5000/api/vulnerabilities?severity=critical,high

# Limit results
curl http://localhost:5000/api/vulnerabilities?limit=20
```

### GET /api/scans

Get list of all scans:

```bash
curl http://localhost:5000/api/scans
```

### GET /api/scan/<filename>

Get details of a specific scan:

```bash
curl http://localhost:5000/api/scan/webapp_scan.json
```

### POST /api/refresh

Refresh dashboard data:

```bash
curl -X POST http://localhost:5000/api/refresh
```

## Integration Examples

### With Automated Scanning

```bash
#!/bin/bash
# scan_and_dashboard.sh

# Run scan
python3 plugins/server-testing/webapp_scanner/webapp_scanner.py \
    https://example.com > results/scan_$(date +%s).json

# Dashboard will auto-detect new scan file
echo "Scan complete! Check dashboard at http://localhost:5000"
```

### With CI/CD

```yaml
# .github/workflows/security-dashboard.yml
name: Security Dashboard

on: [push]

jobs:
  scan-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run Security Scans
        run: |
          mkdir -p results
          python3 plugins/server-testing/webapp_scanner/webapp_scanner.py \
            ${{ secrets.TARGET_URL }} > results/scan.json

      - name: Deploy Dashboard
        run: |
          pip install flask
          python3 dashboard/dashboard.py results &
          # Deploy to your server
```

### Monitoring Multiple Targets

```bash
# monitor.sh
#!/bin/bash

TARGETS=("example1.com" "example2.com" "example3.com")
RESULTS_DIR="monitoring_results"

mkdir -p "$RESULTS_DIR"

# Continuous monitoring
while true; do
    for TARGET in "${TARGETS[@]}"; do
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        echo "Scanning $TARGET..."

        python3 plugins/server-testing/webapp_scanner/webapp_scanner.py \
            "https://$TARGET" > "$RESULTS_DIR/${TARGET}_${TIMESTAMP}.json"
    done

    echo "Scans complete. Check dashboard: http://localhost:5000"
    sleep 3600  # Scan every hour
done
```

### Remote Access Setup

For production deployment with remote access:

```python
# dashboard_production.py
from dashboard import app, dashboard_data

if __name__ == '__main__':
    dashboard_data.results_dir = '/var/security/results'

    # WARNING: Only use in secure environments
    app.run(
        host='0.0.0.0',  # Listen on all interfaces
        port=8080,
        debug=False,
        ssl_context=('cert.pem', 'key.pem')  # HTTPS
    )
```

## Customization

### Change Theme Colors

Edit `templates/index.html` CSS:

```css
.header {
    background: linear-gradient(135deg, #your-color-1, #your-color-2);
}

.stat-card .number {
    background: linear-gradient(135deg, #your-color-1, #your-color-2);
}
```

### Add Custom Sections

Add new sections to `templates/index.html`:

```html
<div class="section">
    <h2 class="section-title">📈 Your Custom Section</h2>
    <div id="customSection"></div>
</div>
```

Add corresponding API endpoint in `dashboard.py`:

```python
@app.route('/api/custom')
def get_custom_data():
    # Your custom logic
    return jsonify(data)
```

### Add Charts

Install Chart.js and add to template:

```html
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<div class="chart-container">
    <canvas id="myChart"></canvas>
</div>

<script>
const ctx = document.getElementById('myChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
            label: 'Vulnerabilities',
            data: [critical, high, medium, low],
            backgroundColor: ['#dc3545', '#ff6b6b', '#ffa500', '#ffd93d']
        }]
    }
});
</script>
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Local Access Only**: By default, dashboard runs on 127.0.0.1 (localhost only)
2. **No Authentication**: Dashboard has no built-in authentication
3. **Sensitive Data**: Scan results may contain sensitive vulnerability information
4. **Production Use**: For production:
   - Use reverse proxy (nginx) with authentication
   - Enable HTTPS
   - Implement access controls
   - Use firewall rules

### Secure Production Setup

```nginx
# /etc/nginx/sites-available/dashboard
server {
    listen 443 ssl;
    server_name dashboard.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    auth_basic "Security Dashboard";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Troubleshooting

### Dashboard not loading data

```bash
# Check if results directory exists
ls -la results/

# Check Flask logs
python3 dashboard.py 2>&1 | tee dashboard.log

# Verify JSON files are valid
python3 -m json.tool results/scan.json
```

### Port already in use

```bash
# Find process using port 5000
lsof -i :5000

# Use different port
python3 dashboard.py results 8080
```

### Cannot access from other machines

By default, Flask only listens on localhost. Edit `dashboard.py`:

```python
app.run(host='0.0.0.0', port=5000)  # Listen on all interfaces
```

⚠️ **Warning**: Only do this in secure/isolated networks!

## Development

### Run in Debug Mode

```python
# dashboard_dev.py
from dashboard import app, dashboard_data

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
```

### Add New Features

1. Add API endpoint in `dashboard.py`
2. Update frontend in `templates/index.html`
3. Test with sample data
4. Document in this README

## Future Enhancements

- Real-time WebSocket updates
- Historical trend analysis
- Export dashboard views as PDF
- Email notifications for critical findings
- User authentication and authorization
- Role-based access control
- Database backend for persistence
- Chart.js integration for visualizations
- Comparison between scans
- Remediation tracking

## License

Part of Penetration Test Suite - Educational/Research Use
