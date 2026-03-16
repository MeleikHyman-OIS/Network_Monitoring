# Network_Monitoring

Network traffic analysis tool for processing Palo Alto firewall logs and matching against threat intelligence feeds.

## Features

- Parses Palo Alto network traffic logs
- Identifies duplicate IP combinations for aggregate analysis
- Matches traffic against threat intelligence IP lists
- Displays full detailed results without truncation

## Requirements

- Python 3.9+
- pandas
- ipaddress (standard library)

## Usage

```bash
python bin/NetworkTraffic.py [log_file_path]
```

If no log file path is provided, defaults to `/var/log/remote/pa_traffic.log`.

## Input Files

- **Log File**: Palo Alto traffic log in CSV format (minimum 47 comma-separated fields)
- **Threat Intelligence**: `ThreatConnectExport_IPs.csv` in the project root directory

## Output

The script prints:
- Column names from parsed log
- Duplicate IP combination counts (aggregated view)
- Matching rows where any IP matches the threat intelligence list

## File Structure

- `bin/NetworkTraffic.py` - Main analysis script
- `ThreatConnectExport_IPs.csv` - Threat intelligence IP list
- `test_pa_traffic.log` - Sample test log file

