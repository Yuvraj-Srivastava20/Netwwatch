"""Shared settings for the NetWatch Phase 1 pipeline.

Everything tunable lives here so the team changes one file, not five.
"""
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------- paths
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
RAW_CSV = DATA_DIR / "events_raw.csv"
GROUND_TRUTH_CSV = DATA_DIR / "ground_truth.csv"
DB_PATH = DATA_DIR / "netwatch.db"
PLOTS_DIR = DATA_DIR / "plots"

# ---------------------------------------------------------------- timeline
SEED = 42
START = datetime(2026, 10, 26)  # a Monday, 00:00
DAYS = 7

# Day 0 is warm-up: it is only used to learn which destinations are "known".
# Days 1-3 are the baseline period (clean, no attacks).
# Days 4-6 contain the injected attacks.
WARMUP_DAYS = 1
BASELINE_FIRST_DAY = 1
BASELINE_LAST_DAY = 3  # inclusive


def day_time(day, hour=0, minute=0, second=0):
    """Datetime for 'day N of the dataset' at the given clock time."""
    return START + timedelta(days=day, hours=hour, minutes=minute, seconds=second)


WARMUP_END = day_time(WARMUP_DAYS)
BASELINE_START = day_time(BASELINE_FIRST_DAY)
BASELINE_END = day_time(BASELINE_LAST_DAY + 1)

# ---------------------------------------------------------------- features
WINDOW = "5min"  # feature window size
FEATURES = [
    "conn_count",
    "unique_ports",
    "unique_dsts",
    "fail_count",
    "bytes_total",
    "new_dst_count",
    "peak_ports_60s",  # max distinct ports in any rolling 60 s span
]

# Minimum std per feature. Stops divide-by-zero for very regular devices.
STD_FLOOR = {
    "conn_count": 1.0,
    "unique_ports": 1.0,
    "unique_dsts": 1.0,
    "fail_count": 0.5,
    "bytes_total": 1000.0,
    "new_dst_count": 0.5,
    "peak_ports_60s": 1.0,
}
MIN_SAMPLES = 12  # fewer samples than this for an hour -> fall back to the device's overall stats


# ---------------------------------------------------------------- device roles
def make_profile(rules, default):
    """24-value hour-of-day traffic multiplier. rules = {(from_hour, to_hour): multiplier}."""
    profile = [default] * 24
    for (lo, hi), value in rules.items():
        for hour in range(lo, hi):
            profile[hour] = value
    return profile


# base = connections per hour at multiplier 1.0
ROLES = {
    "lab_pc": dict(
        prefix="LAB-PC", label="Lab PC", count=30, base=60, pool=15, internal=False,
        ports=[53, 80, 443], port_w=[0.30, 0.35, 0.35],
        profile=make_profile({(8, 9): 0.6, (9, 18): 1.0, (18, 22): 0.35}, 0.03),
    ),
    "student": dict(
        prefix="STUDENT", label="Student laptop", count=50, base=45, pool=25, internal=False,
        ports=[53, 80, 443, 5228, 3478], port_w=[0.2, 0.2, 0.4, 0.1, 0.1],
        profile=make_profile({(7, 9): 0.3, (9, 18): 0.5, (18, 24): 1.0, (0, 2): 0.6, (2, 7): 0.1}, 0.1),
    ),
    "faculty": dict(
        prefix="FAC-PC", label="Faculty PC", count=20, base=40, pool=20, internal=False,
        ports=[22, 53, 80, 443, 8080], port_w=[0.05, 0.2, 0.25, 0.4, 0.1],
        profile=make_profile({(8, 9): 0.5, (9, 18): 1.0, (18, 19): 0.5}, 0.05),
    ),
    "hostel_ap": dict(
        prefix="HOSTEL-AP", label="Hostel AP", count=10, base=200, pool=30, internal=False,
        ports=[53, 80, 443, 993, 5228], port_w=[0.2, 0.2, 0.4, 0.1, 0.1],
        profile=make_profile({(0, 2): 0.8, (2, 7): 0.2, (7, 18): 0.5, (18, 24): 1.0}, 0.5),
    ),
    "server": dict(
        prefix="SERVER", label="Server", count=10, base=100, pool=12, internal=True,
        ports=[443, 3306, 5432, 22, 8080], port_w=[0.4, 0.2, 0.15, 0.05, 0.2],
        profile=make_profile({(8, 20): 1.0}, 0.8),
    ),
    "iot": dict(
        prefix="IOT", label="IoT device", count=8, base=12, pool=3, internal=True,
        ports=[123, 1883, 8883], port_w=[0.2, 0.5, 0.3],
        profile=make_profile({}, 1.0),
    ),
}
