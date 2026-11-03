"""Per-device, per-hour-of-day baselines ("what is normal for this device?") and z-scores.

Baselines use ONLY the baseline period from config.py, never the attack days.
"""
import pandas as pd

from config import BASELINE_END, BASELINE_START, FEATURES, MIN_SAMPLES, STD_FLOOR


def compute_baselines(features, start=BASELINE_START, end=BASELINE_END, min_samples=MIN_SAMPLES):
    """Returns long table: device_id, hour_of_day, feature, mean, std, n_samples."""
    base = features[(features["window_start"] >= start) & (features["window_start"] < end)].copy()
    if base.empty:
        raise ValueError("No feature windows fall inside the baseline period; check config.BASELINE_*")
    base["hour_of_day"] = base["window_start"].dt.hour
    long = base.melt(id_vars=["device_id", "hour_of_day"], value_vars=FEATURES,
                     var_name="feature", value_name="value")

    hourly = (long.groupby(["device_id", "hour_of_day", "feature"])["value"]
              .agg(mean="mean", std="std", n_samples="count").reset_index())
    overall = (long.groupby(["device_id", "feature"])["value"]
               .agg(overall_mean="mean", overall_std="std").reset_index())

    out = hourly.merge(overall, on=["device_id", "feature"])
    sparse = out["n_samples"] < min_samples  # too few samples for this hour -> use the device overall
    out.loc[sparse, "mean"] = out.loc[sparse, "overall_mean"]
    out.loc[sparse, "std"] = out.loc[sparse, "overall_std"]

    floor = out["feature"].map(STD_FLOOR)
    out["std"] = out["std"].fillna(0).clip(lower=floor)
    return out[["device_id", "hour_of_day", "feature", "mean", "std", "n_samples"]]


def zscores(features, baselines):
    """Features + mean_/std_/z_ columns for each feature, using each device's own hourly baseline."""
    wide = baselines.pivot(index=["device_id", "hour_of_day"], columns="feature", values=["mean", "std"])
    wide.columns = [f"{stat}_{feat}" for stat, feat in wide.columns]
    df = features.copy()
    df["hour_of_day"] = df["window_start"].dt.hour
    df = df.merge(wide.reset_index(), on=["device_id", "hour_of_day"], how="left")
    for f in FEATURES:
        df[f"z_{f}"] = (df[f] - df[f"mean_{f}"]) / df[f"std_{f}"]
    return df
