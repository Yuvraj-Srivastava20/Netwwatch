"""SQLite helpers: schema, bulk saves, and loaders."""
import sqlite3

import pandas as pd

from config import DB_PATH

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

SCHEMA = """
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS features;
DROP TABLE IF EXISTS baselines;

CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    src_device  TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    dst_port    INTEGER,
    protocol    TEXT,
    bytes       INTEGER,
    status      TEXT
);
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    role      TEXT,
    name      TEXT
);
CREATE TABLE features (
    device_id      TEXT NOT NULL,
    window_start   TEXT NOT NULL,
    conn_count     INTEGER,
    unique_ports   INTEGER,
    unique_dsts    INTEGER,
    fail_count     INTEGER,
    bytes_total    INTEGER,
    new_dst_count  INTEGER,
    peak_ports_60s INTEGER,
    PRIMARY KEY (device_id, window_start)
);
CREATE TABLE baselines (
    device_id   TEXT NOT NULL,
    hour_of_day INTEGER NOT NULL,
    feature     TEXT NOT NULL,
    mean        REAL,
    std         REAL,
    n_samples   INTEGER,
    PRIMARY KEY (device_id, hour_of_day, feature)
);
"""


def connect(path=DB_PATH):
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path)


def reset_db(conn):
    conn.executescript(SCHEMA)
    conn.commit()


def _stringify(df, col):
    return df.assign(**{col: df[col].dt.strftime(TS_FORMAT)})


def save_events(conn, events):
    cols = ["timestamp", "src_device", "dst_ip", "dst_port", "protocol", "bytes", "status"]
    _stringify(events[cols], "timestamp").to_sql("events", conn, if_exists="append", index=False, chunksize=50_000)


def save_devices(conn, devices):
    devices[["device_id", "role", "name"]].to_sql("devices", conn, if_exists="append", index=False)


def save_features(conn, features):
    _stringify(features, "window_start").to_sql("features", conn, if_exists="append", index=False, chunksize=50_000)


def save_baselines(conn, baselines):
    baselines.to_sql("baselines", conn, if_exists="append", index=False, chunksize=50_000)


def create_indexes(conn):
    # every later query filters on (device, time), so index it
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_dev_ts ON events(src_device, timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_features_ts ON features(window_start)")
    conn.commit()


def load_events(conn, device=None, start=None, end=None):
    """Events for one device and/or time range. start/end are datetimes or 'YYYY-MM-DD HH:MM:SS'."""
    sql, args = "SELECT * FROM events WHERE 1=1", []
    if device:
        sql += " AND src_device = ?"
        args.append(device)
    if start is not None:
        sql += " AND timestamp >= ?"
        args.append(pd.Timestamp(start).strftime(TS_FORMAT))
    if end is not None:
        sql += " AND timestamp < ?"
        args.append(pd.Timestamp(end).strftime(TS_FORMAT))
    return pd.read_sql_query(sql + " ORDER BY timestamp", conn, params=args, parse_dates=["timestamp"])


def load_features(conn):
    return pd.read_sql_query("SELECT * FROM features ORDER BY device_id, window_start", conn,
                             parse_dates=["window_start"])


def load_baselines(conn):
    return pd.read_sql_query("SELECT * FROM baselines", conn)


def load_devices(conn):
    return pd.read_sql_query("SELECT * FROM devices", conn)
