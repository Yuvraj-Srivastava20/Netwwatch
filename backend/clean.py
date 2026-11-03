"""Parsing, normalising and validating raw network logs.

clean_events() takes a raw DataFrame (any CSV with roughly the right columns)
and returns (clean_df, report). The report says how many rows were dropped and why.
"""
import pandas as pd

REQUIRED = ["timestamp", "src_device", "dst_ip", "dst_port", "protocol", "bytes", "status"]

# Map other CSV layouts onto our schema. Add entries (or pass column_map=) for new sources.
COLUMN_ALIASES = {
    "time": "timestamp", "ts": "timestamp", "datetime": "timestamp", "date": "timestamp",
    "src": "src_device", "source": "src_device", "device": "src_device", "src_ip": "src_device",
    "source_ip": "src_device", "host": "src_device",
    "dst": "dst_ip", "dest_ip": "dst_ip", "destination_ip": "dst_ip", "destination": "dst_ip",
    "port": "dst_port", "dest_port": "dst_port", "destination_port": "dst_port",
    "proto": "protocol",
    "bytes_sent": "bytes", "size": "bytes", "length": "bytes", "total_bytes": "bytes",
    "result": "status", "state": "status", "action": "status",
}
SUCCESS = {"success", "ok", "allowed", "allow", "established", "accepted", "s", "1", "true"}
FAIL = {"fail", "failed", "failure", "reject", "rejected", "denied", "deny", "timeout",
        "refused", "reset", "f", "0", "false"}


def _norm_col(name):
    return str(name).strip().lower().replace(" ", "_").replace("-", "_")


def clean_events(raw, column_map=None):
    report = {"rows_in": len(raw)}
    df = raw.copy()
    df.columns = [_norm_col(c) for c in df.columns]
    df = df.rename(columns={**COLUMN_ALIASES, **(column_map or {})})
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f"CSV is missing columns {missing}. Pass column_map={{'your_col': 'timestamp', ...}}.")
    df = df[REQUIRED].copy()

    def drop(mask, reason):
        nonlocal df
        report[reason] = int(mask.sum())
        df = df[~mask].copy()

    # timestamps -> one timezone (UTC, stored naive)
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True, format="mixed")
    df["timestamp"] = ts.dt.tz_convert(None)

    # text fields
    df["src_device"] = df["src_device"].astype("string").str.strip().str.upper().replace("", pd.NA)
    df["dst_ip"] = df["dst_ip"].astype("string").str.strip().replace("", pd.NA)
    drop(df["timestamp"].isna() | df["src_device"].isna() | df["dst_ip"].isna(), "dropped_missing_critical")

    # port must be an integer in 0..65535
    port = pd.to_numeric(df["dst_port"], errors="coerce")
    drop(port.isna() | (port < 0) | (port > 65535) | (port % 1 != 0), "dropped_invalid_port")
    df["dst_port"] = port.loc[df.index].astype("int64")

    # bytes must not be negative (missing -> 0)
    nbytes = pd.to_numeric(df["bytes"], errors="coerce")
    drop(nbytes < 0, "dropped_negative_bytes")
    df["bytes"] = nbytes.loc[df.index].fillna(0).astype("int64")

    # protocol upper-case
    proto = df["protocol"].astype("string").str.strip().str.upper().replace("", pd.NA)
    df["protocol"] = proto.fillna("UNKNOWN")

    # status -> "success" | "fail"
    s = df["status"].astype("string").str.strip().str.lower()
    mapped = s.map(lambda v: "success" if v in SUCCESS else ("fail" if v in FAIL else None))
    drop(mapped.isna(), "dropped_bad_status")
    df["status"] = mapped.loc[df.index]

    drop(df.duplicated(), "dropped_duplicates")

    for col in ("src_device", "dst_ip", "protocol", "status"):
        df[col] = df[col].astype(str)
    df = df.sort_values("timestamp").reset_index(drop=True)
    report["rows_out"] = len(df)
    return df, report


def print_report(report):
    print(f"  rows in            : {report['rows_in']:,}")
    for key, value in report.items():
        if key.startswith("dropped_"):
            print(f"  {key.replace('_', ' '):<19}: {value:,}")
    print(f"  rows out           : {report['rows_out']:,}")
