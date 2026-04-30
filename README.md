# Network Monitoring

Python-based network traffic analysis for Palo Alto firewall logs, with threat-intel IP matching against a local export.

## Current Repository State

- Main analyzer script: `bin/NetworkTraffic.py`
- Threat intelligence source file: `ThreatConnectExport_IPs.csv`
- Sample/test traffic log: `test_pa_traffic.log`
- Active branch: `main` (tracking `origin/main`)

## What the Script Does

`bin/NetworkTraffic.py` performs the following:

1. Reads up to the first 10,000 lines of a Palo Alto traffic log.
2. Extracts fixed-position CSV fields (requires at least 47 fields).
3. Builds duplicate counts for combined source/destination IP tuples.
4. Loads threat IPs from `ThreatConnectExport_IPs.csv`.
5. Compares four IP columns against the threat list and prints matching rows.

## Requirements

- Python 3.9+
- `pandas`

Install dependencies:

```bash
pip install pandas
```

## Usage

Run with an explicit log file:

```bash
python bin/NetworkTraffic.py test_pa_traffic.log
```

Or provide your own log path:

```bash
python bin/NetworkTraffic.py <path_to_pa_traffic_log>
```

If no argument is supplied, the script defaults to:

```text
/var/log/remote/pa_traffic.log
```

## Input Expectations

- Traffic log is comma-separated and includes the expected Palo Alto field positions.
- Each parsed line must contain at least 47 fields, or it is skipped.
- Threat intel CSV must include a `Value` column containing IP addresses.

## Output

The script prints:

- Parsed dataframe column names
- Duplicate IP-combination counts
- Matching rows where any of these columns hit threat intel:
  - `src_ip`
  - `masking_src_ip`
  - `dest_ip`
  - `masking_dest_ip`

## Notes

- The script currently prints all matching results to stdout.
- File paths are resolved relative to the script location for the threat intel CSV.

