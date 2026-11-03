"""Phase 1 sanity checks: are the injected attacks actually visible in the features?

Run after run_phase1.py:   python check.py
"""
import pandas as pd

from baseline import zscores
from config import BASELINE_END, FEATURES, GROUND_TRUTH_CSV, PLOTS_DIR, ROLES, WINDOW
from db import connect, load_baselines, load_features

EXPECTED_FEATURE = {
    "port_scan": "peak_ports_60s",
    "traffic_spike": "conn_count",
    "new_destination": "new_dst_count",
    "repeated_failures": "fail_count",
    "mild_spike": "conn_count",
    "mild_new_destination": "new_dst_count",
}
MIN_Z = 3.0
FALSE_ALARM_Z = 4.0
FALSE_ALARM_FEATURES = ["conn_count", "unique_ports", "fail_count", "new_dst_count", "peak_ports_60s"]


def run_checks(conn, make_plots=True):
    truth = pd.read_csv(GROUND_TRUTH_CSV, parse_dates=["start_time", "end_time"])
    feats, base = load_features(conn), load_baselines(conn)
    zs = zscores(feats, base)

    print("\n1) Row counts")
    n_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"   events: {n_events:,}   feature windows: {len(feats):,}   baseline rows: {len(base):,}")
    by_role = conn.execute(
        "SELECT d.role, COUNT(DISTINCT d.device_id), COUNT(e.id) FROM devices d "
        "LEFT JOIN events e ON e.src_device = d.device_id GROUP BY d.role").fetchall()
    for role, n_dev, n_ev in by_role:
        print(f"   {role:<10} {n_dev:>3} devices  {n_ev:>9,} events")

    print("\n2) Daily pattern (LAB-PC-07 baseline, mean connections per 5 min)")
    pat = base[(base.device_id == "LAB-PC-07") & (base.feature == "conn_count")].set_index("hour_of_day")["mean"]
    print("   " + "   ".join(f"{h:02d}h: {pat[h]:5.1f}" for h in (3, 9, 14, 20)))
    ok_daily = pat[14] > 5 * max(pat[3], 0.01)
    print(f"   daytime >> night: {'PASS' if ok_daily else 'FAIL'}")

    print(f"\n3) Injected attacks vs baseline (pass = max z-score >= {MIN_Z})")
    print(f"   {'device':<13}{'attack':<22}{'feature':<16}{'observed':>9}{'normal':>9}{'max z':>8}  result")
    all_ok = ok_daily
    attack_windows = set()
    for row in truth.itertuples():
        feat = EXPECTED_FEATURE[row.attack_type]
        w0 = row.start_time.floor(WINDOW)
        for w in pd.date_range(w0 - pd.Timedelta(WINDOW), row.end_time, freq=WINDOW):
            attack_windows.add((row.device, w))
        sel = zs[(zs.device_id == row.device) & (zs.window_start >= w0) & (zs.window_start < row.end_time)]
        best = sel.loc[sel[f"z_{feat}"].idxmax()]
        passed = best[f"z_{feat}"] >= MIN_Z
        all_ok &= bool(passed)
        print(f"   {row.device:<13}{row.attack_type:<22}{feat:<16}{best[feat]:>9.0f}"
              f"{best[f'mean_{feat}']:>9.1f}{best[f'z_{feat}']:>8.1f}  {'PASS' if passed else 'FAIL'}")

    print(f"\n4) Noise level after the baseline period (windows with z > {FALSE_ALARM_Z}, attacks excluded)")
    after = zs[zs.window_start >= BASELINE_END].copy()
    keys = list(zip(after.device_id, after.window_start))
    after = after[[k not in attack_windows for k in keys]]
    print(f"   {len(after):,} normal windows checked")
    for f in FALSE_ALARM_FEATURES:
        n = int((after[f"z_{f}"] > FALSE_ALARM_Z).sum())
        print(f"   {f:<16} {n:>5} windows  ({100 * n / len(after):.2f}%)")
    print("   (raw z-scores are noisy on their own; Phase 2 rules + risk scoring will filter this)")

    print(f"\nOVERALL: {'ALL CHECKS PASSED' if all_ok else 'SOME CHECKS FAILED - fix generator/features before Phase 2'}")
    if make_plots:
        _plots(zs, base, truth)
    return all_ok


def _plots(zs, base, truth):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib not installed - skipping plots; pip install matplotlib)")
        return
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(7, 3.5))
    for dev in ("LAB-PC-07", "STUDENT-42", "HOSTEL-AP-03"):
        s = base[(base.device_id == dev) & (base.feature == "conn_count")].sort_values("hour_of_day")
        ax.plot(s["hour_of_day"], s["mean"], marker="o", label=dev)
    ax.set_xlabel("hour of day")
    ax.set_ylabel("connections per 5 min (baseline mean)")
    ax.set_title("Each device has its own daily rhythm")
    ax.legend()
    fig.tight_layout()
    fig.savefig(PLOTS_DIR / "daily_pattern.png", dpi=130)
    plt.close(fig)

    scan = truth[truth.attack_type == "port_scan"].iloc[0]
    day = scan.start_time.normalize()
    sel = zs[(zs.device_id == scan.device) & (zs.window_start >= day + pd.Timedelta(hours=8))
             & (zs.window_start < day + pd.Timedelta(hours=11))]
    fig, ax = plt.subplots(figsize=(7, 3.5))
    ax.bar(sel["window_start"], sel["peak_ports_60s"], width=0.003, color="tab:red")
    ax.plot(sel["window_start"], sel["mean_peak_ports_60s"] + 3 * sel["std_peak_ports_60s"], "k--",
            label="baseline mean + 3 std")
    ax.set_ylabel("max distinct ports in 60 s")
    ax.set_title(f"{scan.device}: injected port scan")
    ax.legend()
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(PLOTS_DIR / "port_scan_lab_pc_07.png", dpi=130)
    plt.close(fig)
    print(f"plots saved to {PLOTS_DIR}")


if __name__ == "__main__":
    run_checks(connect())
