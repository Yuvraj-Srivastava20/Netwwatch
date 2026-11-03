"""Turn events into one row per device per 5-minute window.

Output columns: device_id, window_start + the FEATURES in config.py.
Windows with no traffic are kept as zeros (needed for honest baselines).
"""
import numpy as np
import pandas as pd

from config import FEATURES, WARMUP_END, WINDOW


def _rolling_unique(secs, items, span=60):
    """For each event, number of distinct items among events in the last `span` seconds."""
    out = np.empty(len(secs), dtype=np.int32)
    counts, left = {}, 0
    for right in range(len(secs)):
        item = items[right]
        counts[item] = counts.get(item, 0) + 1
        while secs[right] - secs[left] >= span:
            old = items[left]
            if counts[old] == 1:
                del counts[old]
            else:
                counts[old] -= 1
            left += 1
        out[right] = len(counts)
    return out


def _peak_ports_60s(ev):
    """True rolling 60 s distinct-port count per event (ev must be sorted by device, time)."""
    out = np.zeros(len(ev), dtype=np.int32)
    secs = ev["secs"].to_numpy()
    ports = ev["dst_port"].to_numpy()
    for _, pos in ev.groupby("device_id", sort=False).indices.items():
        out[pos] = _rolling_unique(secs[pos].tolist(), ports[pos].tolist())
    return out


def build_features(events, devices=None, start=None, end=None, warmup_end=WARMUP_END):
    """events: clean DataFrame. devices: optional devices table so silent devices still get rows."""
    ev = events.rename(columns={"src_device": "device_id"})
    ev = ev.sort_values(["device_id", "timestamp"]).reset_index(drop=True)
    ev["secs"] = (ev["timestamp"] - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=1)
    ev["window_start"] = ev["timestamp"].dt.floor(WINDOW)
    ev["is_fail"] = (ev["status"] == "fail").astype("int64")
    ev["ports_60s"] = _peak_ports_60s(ev)

    agg = ev.groupby(["device_id", "window_start"]).agg(
        conn_count=("timestamp", "size"),
        unique_ports=("dst_port", "nunique"),
        unique_dsts=("dst_ip", "nunique"),
        fail_count=("is_fail", "sum"),
        bytes_total=("bytes", "sum"),
        peak_ports_60s=("ports_60s", "max"),
    )

    # New destination = first time this device ever contacts that IP, after the warm-up period.
    first_seen = ev.groupby(["device_id", "dst_ip"])["timestamp"].min().reset_index()
    first_seen = first_seen[first_seen["timestamp"] >= warmup_end]
    first_seen["window_start"] = first_seen["timestamp"].dt.floor(WINDOW)
    new_counts = first_seen.groupby(["device_id", "window_start"]).size().rename("new_dst_count")

    feats = agg.join(new_counts, how="left").fillna({"new_dst_count": 0})

    # full grid: every device x every window, zeros where nothing happened
    start = start or ev["timestamp"].min().floor("D")
    end = end or ev["timestamp"].max().floor("D") + pd.Timedelta(days=1)
    windows = pd.date_range(start, end, freq=WINDOW, inclusive="left")
    ids = set(ev["device_id"])
    if devices is not None:
        ids |= set(devices["device_id"])
    grid = pd.MultiIndex.from_product([sorted(ids), windows], names=["device_id", "window_start"])
    feats = feats.reindex(grid, fill_value=0).astype("int64")
    return feats.reset_index()[["device_id", "window_start"] + FEATURES]
