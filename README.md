# Cloudflare IP Monitor

A comprehensive solution for discovering and monitoring optimal Cloudflare CDN IP addresses. This tool helps you find the fastest, most reliable Cloudflare IPs based on your network conditions.

## Features

### 1. Initial IP Discovery (Step 1)
- Scans ALL Cloudflare IP ranges automatically
- Filters IPs by configurable criteria:
  - Download/Upload speed >= 10 MB/s
  - Loss rate < 25%
  - Latency < 1000ms
- Uses the CloudflareScanner binary for accurate testing

### 2. Periodic Monitoring (Step 2)
- Continuously tests discovered IPs at configurable intervals (default: 2 minutes)
- Tracks historical performance data:
  - Download/Upload speeds
  - Latency measurements
  - Packet loss rates
- Automatically updates statistics

### 3. Web Dashboard (Step 3)
- Pure Python web interface (no external dependencies!)
- Real-time statistics and metrics
- Searchable, sortable IP table
- IP detail views with historical data
- Hourly performance charts
- Monitor control (start/stop/configure)
- Export functionality

## Requirements

- Python 3.7+
- No external Python dependencies (uses only standard library)
- Internet connection for downloading CloudflareScanner binary

## Installation

1. Clone or download this repository:
```bash
git clone <repository-url>
cd cloudflare-ip-monitor
```

2. Run the tool (it will auto-download the CloudflareScanner binary):
```bash
python main.py all
```

## Usage

### Quick Start (Recommended)
```bash
# Run everything: initial scan (if needed) + dashboard + monitoring
python main.py all
```

Then open your browser to: http://localhost:8080

### Individual Commands

#### Initial Scan
```bash
# Basic scan with default settings (10 MB/s min speed)
python main.py scan

# Custom criteria
python main.py scan -s 15 -l 500 -r 0.1
# -s: Minimum speed (MB/s)
# -l: Maximum latency (ms)
# -r: Maximum loss rate (0-1)
```

#### Periodic Monitoring
```bash
# Start monitoring every 2 minutes (default)
python main.py monitor

# Custom interval (5 minutes)
python main.py monitor -i 300
```

#### Web Dashboard
```bash
# Start dashboard only
python main.py dashboard

# Custom host/port
python main.py dashboard --host 127.0.0.1 --port 9000
```

#### Status Check
```bash
python main.py status
```

#### Export IPs
```bash
# Export to text file (one IP per line)
python main.py export -o best_ips.txt

# Export to CSV with details
python main.py export -o ips.csv -f csv

# Export to JSON
python main.py export -o ips.json -f json
```

## Configuration

Edit `config.py` to customize default settings:

```python
# Initial scan parameters
INITIAL_SCAN_CONFIG = {
    "min_speed": 10.0,           # MB/s
    "max_loss_rate": 0.25,       # 25%
    "max_latency": 1000,         # ms
    "test_count": 50,            # IPs to download test
    "threads": 300,              # Concurrent threads
}

# Periodic monitoring
MONITOR_CONFIG = {
    "interval_seconds": 120,     # 2 minutes
    "max_ips_per_cycle": 20,     # IPs per test cycle
}

# Dashboard
DASHBOARD_CONFIG = {
    "host": "0.0.0.0",
    "port": 8080,
}
```

## Dashboard Features

### Statistics Overview
- Total active IPs
- Total tests performed
- Average/Best speed and latency

### IP Table
- Search by IP address
- Sort by any column
- Click IP for detailed history
- Deactivate underperforming IPs

### Monitor Control
- Start/Stop monitoring
- Adjust test interval
- Trigger immediate test
- Run new initial scan

### Charts
- 24-hour performance trends
- Per-IP historical data

## API Endpoints

The dashboard provides a REST API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Overall statistics |
| `/api/ips` | GET | List all IPs with filters |
| `/api/ip?ip=x.x.x.x` | GET | Single IP details |
| `/api/history?ip=x.x.x.x` | GET | IP test history |
| `/api/hourly` | GET | Hourly aggregated stats |
| `/api/monitor/status` | GET | Monitor status |
| `/api/monitor/start` | POST | Start monitoring |
| `/api/monitor/stop` | POST | Stop monitoring |
| `/api/scan/initial` | POST | Trigger initial scan |
| `/api/scan/test` | POST | Trigger immediate test |

## File Structure

```
cloudflare-ip-monitor/
├── main.py          # Main entry point with CLI
├── config.py        # Configuration settings
├── database.py      # SQLite database handler
├── scanner.py       # CloudflareScanner wrapper
├── monitor.py       # Periodic monitoring logic
├── dashboard.py     # Pure Python web server
├── scanner/         # CloudflareScanner binary location
├── data/            # Database and temp files
└── logs/            # Log files
```

## Database

Data is stored in SQLite (`data/cloudflare_ips.db`):

- `ips`: Discovered IP addresses with aggregated stats
- `test_results`: Individual test results (historical)
- `scan_sessions`: Initial scan records

Data is automatically cleaned up after 30 days (configurable).

## Tips for Best Results

1. **First Run**: Use `python main.py all` for automatic setup
2. **Adjust Criteria**: If you get few results, lower the speed requirement
3. **Monitor Interval**: 2-5 minutes is recommended for good balance
4. **Export for Use**: Export best IPs to use in your proxy/VPN configuration

## Troubleshooting

### "No IPs found"
- Lower the minimum speed requirement (`-s 5`)
- Increase max latency (`-l 2000`)
- Check your internet connection

### "CloudflareScanner not found"
- The binary is auto-downloaded on first run
- If download fails, manually download from:
  https://github.com/bia-pain-bache/Cloudflare-Clean-IP-Scanner/releases
- Place in the `scanner/` directory

### "Permission denied"
- On Linux/macOS: `chmod +x scanner/CloudflareScanner`

## License

This tool uses the CloudflareScanner project (GPL-3.0 License).

## Acknowledgments

- [CloudflareScanner](https://github.com/bia-pain-bache/Cloudflare-Clean-IP-Scanner) - The scanning engine
- Cloudflare - For providing public IP ranges
