# Security Testing Report Generator

Professional report generation system for security scan results.

## Features

✅ Multiple output formats (HTML, JSON, CSV, Markdown)
✅ Executive summary with risk assessment
✅ Detailed vulnerability tables
✅ Statistics and charts
✅ Severity-based filtering
✅ Remediation recommendations
✅ Professional styling with print support

## Usage

### Basic Usage

```bash
# Generate HTML report from scan results directory
python3 report_generator.py results/

# Generate JSON report
python3 report_generator.py results/ '{"format": "json"}'

# Filter by severity
python3 report_generator.py results/ '{"format": "html", "severity": "critical,high"}'

# Custom output name
python3 report_generator.py results/ '{"format": "html", "output": "my_report"}'
```

### Options

```json
{
  "format": "html|json|csv|markdown",
  "output": "report_name",
  "severity": "critical,high,medium,low,info|all",
  "include_info": true|false,
  "executive_summary": true|false
}
```

## Report Formats

### HTML Report

Professional web-based report with:
- Executive summary
- Statistics dashboard
- Severity breakdown
- Detailed vulnerability table
- Remediation recommendations
- Print-friendly design

```bash
python3 report_generator.py results/ '{"format": "html"}'
```

### JSON Report

Structured data for integration:

```bash
python3 report_generator.py results/ '{"format": "json"}'
```

### CSV Report

Spreadsheet-compatible format:

```bash
python3 report_generator.py results/ '{"format": "csv"}'
```

### Markdown Report

Documentation-friendly format:

```bash
python3 report_generator.py results/ '{"format": "markdown"}'
```

## Risk Level Calculation

The report automatically calculates overall risk level:

- **CRITICAL**: One or more critical vulnerabilities
- **HIGH**: More than 5 high severity issues
- **MEDIUM**: High severity issues or many medium issues
- **LOW**: Only medium severity issues
- **MINIMAL**: Only low/info findings

## Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/security-report.yml
- name: Generate Security Report
  run: |
    python3 reporting/report_generator.py results/ '{
      "format": "html",
      "severity": "critical,high,medium",
      "output": "security-report-${{ github.run_id }}"
    }'

- name: Upload Report
  uses: actions/upload-artifact@v2
  with:
    name: security-report
    path: security-report-*.html
```

### Automated Scanning & Reporting

```bash
#!/bin/bash
# scan_and_report.sh

TARGET="https://example.com"
RESULTS_DIR="scan_results_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"

# Run scans
python3 plugins/server-testing/webapp_scanner/webapp_scanner.py "$TARGET" \
    > "$RESULTS_DIR/webapp_scan.json"

python3 plugins/api-testing/api_exploiter/api_exploiter.py "$TARGET" \
    > "$RESULTS_DIR/api_scan.json"

# Generate reports in multiple formats
python3 reporting/report_generator.py "$RESULTS_DIR" '{"format": "html"}'
python3 reporting/report_generator.py "$RESULTS_DIR" '{"format": "json"}'
python3 reporting/report_generator.py "$RESULTS_DIR" '{"format": "csv"}'

echo "Reports generated in $RESULTS_DIR"
```

### Multiple Target Reporting

```bash
# Scan multiple targets and generate consolidated report
TARGETS=("example1.com" "example2.com" "example3.com")
RESULTS_DIR="multi_target_scan"

mkdir -p "$RESULTS_DIR"

for TARGET in "${TARGETS[@]}"; do
    echo "Scanning $TARGET..."
    python3 plugins/server-testing/webapp_scanner/webapp_scanner.py \
        "https://$TARGET" > "$RESULTS_DIR/${TARGET}_scan.json"
done

# Generate consolidated report
python3 reporting/report_generator.py "$RESULTS_DIR" '{
    "format": "html",
    "output": "consolidated_report",
    "severity": "all"
}'
```

## Result File Format

The report generator expects JSON files with this structure:

```json
{
  "target": "https://example.com",
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "severity": "critical",
      "description": "SQL injection in login form",
      "url": "https://example.com/login",
      "parameter": "username",
      "payload": "' OR '1'='1"
    }
  ],
  "findings": [...],
  "stats": {...}
}
```

## Customization

### Adding Custom Severity Levels

Edit `calculate_risk_level()` method:

```python
def calculate_risk_level(self):
    critical = self.stats['by_severity']['critical']
    high = self.stats['by_severity']['high']

    # Custom logic
    if critical >= 10:
        return "CATASTROPHIC"
    elif critical > 0:
        return "CRITICAL"
    # ...
```

### Custom HTML Styling

Modify the CSS in `generate_html_report()` method to match your branding.

### Adding Charts

The HTML report supports chart libraries. Add to template:

```html
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<canvas id="myChart"></canvas>
<script>
    // Your chart configuration
</script>
```

## Best Practices

1. **Regular Reporting**: Generate reports after each scan
2. **Archive Reports**: Keep historical reports for trend analysis
3. **Share Appropriately**: Reports may contain sensitive information
4. **Remediation Tracking**: Use reports to track fix progress
5. **Executive vs Technical**: Generate filtered reports for different audiences

## Troubleshooting

### No vulnerabilities in report

- Check scan result files are valid JSON
- Verify `vulnerabilities` key exists in results
- Check severity filter settings

### Missing data

- Ensure all scan result files are in the specified directory
- Check file permissions
- Verify JSON structure matches expected format

### Large reports

- Use severity filtering to reduce size
- Split into multiple reports by target
- Consider paginating HTML reports

## Future Enhancements

- PDF export with WeasyPrint
- Chart.js integration for visualizations
- Trend analysis across multiple reports
- JIRA/GitHub issue creation from findings
- Email report delivery
- Customizable templates

## License

Part of Penetration Test Suite - Educational/Research Use
