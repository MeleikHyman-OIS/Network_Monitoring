import ipaddress
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import sys
import os

# Configure pandas to display full DataFrames without truncation
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

# ─── Helpers ───────────────────────────────────────────────────────────────────
def safe_int(ip_str):
    try:
        return int(ipaddress.ip_address(ip_str))
    except Exception:
        return None

def extract_fields(line: str):
    parts = line.strip().split(',')
    #print("Parts:", parts[:23])
    # need at least 47 items (0–46)
    if len(parts) < 47:
        return None

    # fixed‑position fields
    timestamp                = parts[1]
    session_id               = parts[22]
    port_number              = parts[24]
    src_ip                   = parts[7]
    masking_src_ip           = parts[8]
    dest_ip                  = parts[9]
    masking_dest_ip          = parts[10]
    application              = parts[14] if len(parts) > 14 else None

    # your hard‑coded offsets
    action                   = parts[30].lower()
    total_bytes              = parts[31]
    sent_bytes               = parts[32]
    received_bytes           = parts[33]
    total_packets            = parts[34]
    packets_sent             = parts[44]
    packets_received         = parts[45]
    reason_for_session_end   = parts[46]

    # bail if action is empty
    if not action:
        return None

    return {
        'timestamp':                timestamp,
        'session_id':               session_id,
        'port_number':              port_number,
        'application':              application,
        'action':                   action,
        'src_ip':                   src_ip,
        'masking_src_ip':           masking_src_ip,
        'dest_ip':                  dest_ip,
        'masking_dest_ip':          masking_dest_ip,
        'total_bytes':              total_bytes,
        'sent_bytes':               sent_bytes,
        'received_bytes':           received_bytes,
        'total_packets':            total_packets,
        'packets_sent':             packets_sent,
        'packets_received':         packets_received,
        'reason_for_session_end':   reason_for_session_end,
    }

# ─── 1) Read & Parse ───────────────────────────────────────────────────────────
if len(sys.argv) > 1:
    LOG_PATH = sys.argv[1]
else:
    LOG_PATH = '/var/log/remote/pa_traffic.log'

with open(LOG_PATH, 'r') as f:
    first_lines = [f.readline() for _ in range(10000)]

with ThreadPoolExecutor() as exe:
    recs = list(exe.map(extract_fields, first_lines))

records = [r for r in recs if isinstance(r, dict)]
df = pd.DataFrame(records)
print("Columns:", df.columns.tolist())

# ─── 2) Duplicate Counts ───────────────────────────────────────────────────────
df['combined_ips'] = (
    df['src_ip'] + ',' +
    df['masking_src_ip'] + ',' +
    df['dest_ip'] + ',' +
    df['masking_dest_ip']
)
dup_counts = df.groupby('combined_ips').size().reset_index(name='count')
print("Duplicate counts:\n", dup_counts)

# ─── 3) Load & Hash External IP List ──────────────────────────────────────────
# Get the script's directory and go up one level to find the CSV file
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
IP_LIST_PATH = os.path.join(project_root, 'ThreatConnectExport_IPs.csv')
ip_vals    = set(pd.read_csv(IP_LIST_PATH)['Value'])
hashed_set = {safe_int(ip) for ip in ip_vals if safe_int(ip) is not None}

# ─── 4) Hash Your Four IP Columns ─────────────────────────────────────────────
IP_COLS = ['src_ip','masking_src_ip','dest_ip','masking_dest_ip']
for col in IP_COLS:
    df[f'h_{col}'] = df[col].apply(safe_int)

df2 = df.dropna(subset=[f'h_{c}' for c in IP_COLS]).copy()

# ─── 5) Build Matching Rows File (with all fields) ────────────────────────────
matches = []
for col in IP_COLS:
    mask = df2[f'h_{col}'].isin(hashed_set)
    tmp  = df2[mask].copy()
    tmp['matching_ip']    = tmp[col]
    tmp['matched_column'] = col
    tmp['matched_ip']     = tmp[col]

    # here’s where we include session_id & port_number
    matches.append(
        tmp[[
            'timestamp','session_id','port_number','application','action',
            'matching_ip','matched_column','matched_ip',
            'total_bytes','sent_bytes','received_bytes',
            'total_packets','packets_sent','packets_received',
            'reason_for_session_end'
        ]]
    )

matching_rows = pd.concat(matches, ignore_index=True)
print("Matching rows:\n", matching_rows)
