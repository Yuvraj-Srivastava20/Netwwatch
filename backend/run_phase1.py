"""Run all of Phase 1:  generate -> clean -> SQLite -> features -> baselines -> checks.

    python run_phase1.py                 # clean synthetic data
    python run_phase1.py --messy         # add dirty rows so you can see clean.py work
    python run_phase1.py --scale 0.3     # smaller/faster dataset while developing
"""
import argparse
import time

import pandas as pd

import db
from baseline import compute_baselines
from check import run_checks
from clean import clean_events, print_report
from config import DB_PATH, RAW_CSV
from features import build_features
from generate_data import generate_all, write_raw


def stage(title):
    print(f"\n== {title}")
    return time.perf_counter()


def done(t0):
    print(f"   ({time.perf_counter() - t0:.1f}s)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--messy", action="store_true")
    parser.add_argument("--scale", type=float, default=1.0)
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()

    t = stage("1. Generate synthetic traffic + inject attacks")
    events, devices, truth = generate_all(args.scale)
    write_raw(events, truth, messy=args.messy)
    print(f"   {len(events):,} events, {len(devices)} devices, {len(truth)} injected attacks -> {RAW_CSV}")
    done(t)

    t = stage("2. Clean the raw CSV")
    clean, report = clean_events(pd.read_csv(RAW_CSV))
    print_report(report)
    done(t)

    t = stage("3. Load into SQLite")
    conn = db.connect()
    db.reset_db(conn)
    db.save_devices(conn, devices)
    db.save_events(conn, clean)
    db.create_indexes(conn)
    print(f"   {DB_PATH}")
    done(t)

    t = stage("4. Feature extraction (5-minute windows)")
    features = build_features(clean, devices)
    db.save_features(conn, features)
    print(f"   {len(features):,} device-windows")
    done(t)

    t = stage("5. Per-device, per-hour baselines")
    baselines = compute_baselines(features)
    db.save_baselines(conn, baselines)
    print(f"   {len(baselines):,} baseline rows")
    done(t)

    t = stage("6. Sanity checks")
    run_checks(conn, make_plots=not args.no_plots)
    done(t)
    conn.close()


if __name__ == "__main__":
    main()
