"""Synthetic campus network traffic + injected attacks (with ground truth).

Run on its own:   python generate_data.py [--messy] [--scale 1.0]
Writes:           data/events_raw.csv, data/ground_truth.csv
"""
import argparse
import random
from datetime import timedelta

import numpy as np
import pandas as pd

from config import (DATA_DIR, DAYS, GROUND_TRUTH_CSV, RAW_CSV, ROLES, SEED, START, day_time)

COLUMNS = ["timestamp", "src_device", "dst_ip", "dst_port", "protocol", "bytes", "status"]
INTERNAL_POOL = [f"10.10.0.{i}" for i in range(2, 22)]
ATTACK_POOL = [f"185.220.101.{i}" for i in range(10, 40)]  # never used by normal traffic
SCAN_TARGET = "10.10.0.5"
RARE_PROB = 0.01  # share of normal connections that go to a rarely used IP
FAIL_RATE = 0.03  # share of normal connections that fail


# ------------------------------------------------------------------ devices
def build_devices(rng):
    rows = []
    for role, cfg in ROLES.items():
        for i in range(1, cfg["count"] + 1):
            rows.append({
                "device_id": f"{cfg['prefix']}-{i:02d}",  # LAB-PC-07, STUDENT-42, ...
                "role": role,
                "name": f"{cfg['label']} {i:02d}",
                "scale": float(rng.lognormal(0, 0.2)),  # each device is a bit busier/quieter
            })
    return pd.DataFrame(rows)


def make_public_pool(rng, n=400):
    pool = set()
    while len(pool) < n:
        ip = f"{rng.integers(20, 200)}.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}"
        if not ip.startswith("185.220.101."):
            pool.add(ip)
    return sorted(pool)


def build_models(devices, rng, public_pool):
    """Per-device behaviour: usual destinations (zipf weighted), rare destinations, role config."""
    models = {}
    for row in devices.itertuples():
        cfg = ROLES[row.role]
        source = INTERNAL_POOL if cfg["internal"] else public_pool
        usual = rng.choice(source, size=cfg["pool"], replace=False)
        weights = 1.0 / np.arange(1, len(usual) + 1)
        weights /= weights.sum()
        usual_set = set(usual.tolist())
        rare = np.array([ip for ip in source if ip not in usual_set])
        models[row.device_id] = dict(cfg=cfg, scale=row.scale, usual=usual, w=weights, rare=rare)
    return models


def expected_rate(model, hour_of_day, scale=1.0):
    """Expected connections per hour for this device at this hour of day."""
    return model["cfg"]["base"] * model["scale"] * model["cfg"]["profile"][hour_of_day] * scale


# ------------------------------------------------------------------ event generation
def gen_events(rng, device_id, model, hour_starts, lam):
    """Poisson number of connections in each given hour, spread uniformly across that hour."""
    cfg = model["cfg"]
    counts = rng.poisson(lam)
    n = int(counts.sum())
    hour_idx = np.repeat(np.arange(len(lam)), counts)
    secs = rng.integers(0, 3600, n).astype("timedelta64[s]")
    ts = hour_starts[hour_idx] + secs
    is_rare = rng.random(n) < RARE_PROB
    usual_pick = rng.choice(model["usual"], n, p=model["w"])
    rare_pick = rng.choice(model["rare"], n)
    port = rng.choice(cfg["ports"], n, p=cfg["port_w"])
    return pd.DataFrame({
        "timestamp": ts,
        "src_device": device_id,
        "dst_ip": np.where(is_rare, rare_pick, usual_pick),
        "dst_port": port,
        "protocol": np.where(np.isin(port, [53, 123]), "UDP", "TCP"),
        "bytes": rng.lognormal(7.5, 1.5, n).astype(np.int64) + 40,
        "status": np.where(rng.random(n) < FAIL_RATE, "fail", "success"),
    })


def generate_normal(rng, models, scale):
    hours = np.arange(DAYS * 24)
    hour_starts = np.datetime64(START, "s") + (hours * 3600).astype("timedelta64[s]")
    parts = []
    for device_id, model in models.items():
        profile = np.tile(model["cfg"]["profile"], DAYS)
        lam = model["cfg"]["base"] * model["scale"] * profile * scale
        parts.append(gen_events(rng, device_id, model, hour_starts, lam))
    return pd.concat(parts, ignore_index=True)


# ------------------------------------------------------------------ attacks
def _manual(rng, device, times, dst_ips, ports, status):
    n = len(times)
    return pd.DataFrame({
        "timestamp": pd.to_datetime(times),
        "src_device": device,
        "dst_ip": dst_ips,
        "dst_port": ports,
        "protocol": "TCP",
        "bytes": rng.integers(60, 400, n),
        "status": status,
    })


def inject_attacks(rng, models, scale):
    """Returns (attack_events, ground_truth). Every attack is recorded in ground truth."""
    parts, truth = [], []

    def record(device, kind, start, end, severity):
        truth.append({"device": device, "attack_type": kind, "start_time": start,
                      "end_time": end, "expected_severity": severity})

    # 1) Port scan: LAB-PC-07 touches 14 distinct ports within one minute (matches the slides)
    t0 = day_time(4, 9, 18)
    ports = [21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080]
    status = ["success" if p in (22, 80, 443) else "fail" for p in ports]
    times = [t0 + timedelta(seconds=4 * i) for i in range(len(ports))]
    parts.append(_manual(rng, "LAB-PC-07", times, [SCAN_TARGET] * len(ports), ports, status))
    record("LAB-PC-07", "port_scan", t0, t0 + timedelta(seconds=60), "high")

    # 2) Traffic spike: HOSTEL-AP-03 sends ~6x its normal volume for an hour
    dev = "HOSTEL-AP-03"
    lam = expected_rate(models[dev], 14, scale) * 5  # 5 extra on top of normal = 6x
    hour = np.array([np.datetime64(day_time(5, 14), "s")])
    parts.append(gen_events(rng, dev, models[dev], hour, np.array([lam])))
    record(dev, "traffic_spike", day_time(5, 14), day_time(5, 15), "high")

    # 3) New destinations: STUDENT-42 suddenly talks to 8 IPs it has never used
    t0 = day_time(5, 21)
    times, dst = [], []
    for i, ip in enumerate(ATTACK_POOL[:8]):
        for k in range(3):
            times.append(t0 + timedelta(seconds=75 * i + 20 * k))
            dst.append(ip)
    parts.append(_manual(rng, "STUDENT-42", times, dst, [443] * len(times), ["success"] * len(times)))
    record("STUDENT-42", "new_destination", t0, t0 + timedelta(minutes=10), "high")

    # 4) Repeated failures: FAC-PC-11 fails 25 SSH logins in under 5 minutes
    t0 = day_time(6, 11)
    times = [t0 + timedelta(seconds=12 * i) for i in range(25)]
    parts.append(_manual(rng, "FAC-PC-11", times, ["10.10.0.7"] * 25, [22] * 25, ["fail"] * 25))
    record("FAC-PC-11", "repeated_failures", t0, t0 + timedelta(minutes=5), "high")

    # 5) Mild spike (should score Medium): LAB-PC-12 at 2.5x normal for an hour
    dev = "LAB-PC-12"
    lam = expected_rate(models[dev], 15, scale) * 1.5
    hour = np.array([np.datetime64(day_time(5, 15), "s")])
    parts.append(gen_events(rng, dev, models[dev], hour, np.array([lam])))
    record(dev, "mild_spike", day_time(5, 15), day_time(5, 16), "medium")

    # 6) Mild new destination: IOT-03 contacts 2 unknown IPs at night
    t0 = day_time(6, 3)
    times, dst = [], []
    for i, ip in enumerate(ATTACK_POOL[8:10]):
        for k in range(3):
            times.append(t0 + timedelta(seconds=150 * i + 30 * k))
            dst.append(ip)
    parts.append(_manual(rng, "IOT-03", times, dst, [443] * len(times), ["success"] * len(times)))
    record("IOT-03", "mild_new_destination", t0, t0 + timedelta(minutes=10), "medium")

    return pd.concat(parts, ignore_index=True), pd.DataFrame(truth)


# ------------------------------------------------------------------ messy export (to exercise clean.py)
def make_messy(df, rng):
    d = df.copy()
    d["timestamp"] = d["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    n = len(d)
    idx = rng.choice(n, int(n * 0.01), replace=False)  # harmless case noise
    d.loc[idx, "protocol"] = d.loc[idx, "protocol"].str.lower()
    idx = rng.choice(n, int(n * 0.01), replace=False)  # different status vocabulary
    d.loc[idx, "status"] = d.loc[idx, "status"].map({"success": "OK", "fail": "Failed"})
    bad = rng.choice(n, int(n * 0.001) * 3, replace=False)  # genuinely bad rows
    third = len(bad) // 3
    d.loc[bad[:third], "timestamp"] = "not-a-time"
    d.loc[bad[third:2 * third], "dst_port"] = 99999
    d.loc[bad[2 * third:], "bytes"] = -1
    dupes = d.sample(int(n * 0.001), random_state=SEED)  # exact duplicates
    return pd.concat([d, dupes]).sample(frac=1, random_state=SEED).reset_index(drop=True)


# ------------------------------------------------------------------ entry point
def generate_all(scale=1.0):
    random.seed(SEED)
    np.random.seed(SEED)
    rng = np.random.default_rng(SEED)
    devices = build_devices(rng)
    models = build_models(devices, rng, make_public_pool(rng))
    normal = generate_normal(rng, models, scale)
    attacks, truth = inject_attacks(rng, models, scale)
    events = pd.concat([normal, attacks], ignore_index=True)
    events = events.sort_values("timestamp").reset_index(drop=True)[COLUMNS]
    return events, devices.drop(columns="scale"), truth


def write_raw(events, truth, messy=False):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out = make_messy(events, np.random.default_rng(SEED + 1)) if messy else events
    out.to_csv(RAW_CSV, index=False, date_format="%Y-%m-%d %H:%M:%S")
    truth.to_csv(GROUND_TRUTH_CSV, index=False, date_format="%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--messy", action="store_true", help="add dirty rows to test clean.py")
    parser.add_argument("--scale", type=float, default=1.0, help="traffic volume multiplier")
    args = parser.parse_args()
    ev, dev, tr = generate_all(args.scale)
    write_raw(ev, tr, args.messy)
    print(f"{len(ev):,} events, {len(dev)} devices, {len(tr)} injected attacks -> {RAW_CSV}")
