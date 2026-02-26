#!/usr/bin/env python
"""Advanced EDA for joined train/test datasets with attack-entity analysis."""

from __future__ import annotations

import argparse
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd


KEY_FEATURES = [
    "Rate",
    "Srate",
    "Drate",
    "Tot sum",
    "Min",
    "Max",
    "AVG",
    "Std",
    "IAT",
    "Number",
    "Weight",
    "TCP",
    "UDP",
    "ARP",
    "ICMP",
    "DNS",
    "HTTP",
    "HTTPS",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run advanced EDA on joined train/test CSVs.")
    parser.add_argument(
        "--train-path",
        type=Path,
        default=Path("eda/data/joined/attacks_train_joined.csv"),
    )
    parser.add_argument(
        "--test-path",
        type=Path,
        default=Path("eda/data/joined/attacks_test_joined.csv"),
    )
    parser.add_argument(
        "--inventory-path",
        type=Path,
        default=Path("eda/data/joined/attacks_file_inventory.csv"),
    )
    parser.add_argument(
        "--out-tables-dir",
        type=Path,
        default=Path("eda/outputs/tables/advanced_eda"),
    )
    parser.add_argument(
        "--out-report",
        type=Path,
        default=Path("eda/outputs/reports/advanced_eda_summary.md"),
    )
    parser.add_argument("--chunk-size", type=int, default=250_000)
    parser.add_argument("--sample-frac", type=float, default=0.02)
    parser.add_argument("--sample-max-rows", type=int, default=400_000)
    return parser.parse_args()


def _psi(train_s: pd.Series, test_s: pd.Series, bins: int = 10) -> float:
    train_s = pd.to_numeric(train_s, errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
    test_s = pd.to_numeric(test_s, errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
    if len(train_s) < 50 or len(test_s) < 50:
        return np.nan
    quantiles = np.linspace(0, 1, bins + 1)
    edges = np.unique(np.quantile(train_s, quantiles))
    if len(edges) < 3:
        return 0.0
    tr = pd.cut(train_s, bins=edges, include_lowest=True).value_counts(normalize=True, sort=False)
    te = pd.cut(test_s, bins=edges, include_lowest=True).value_counts(normalize=True, sort=False)
    tr = tr.reindex(tr.index, fill_value=1e-8)
    te = te.reindex(tr.index, fill_value=1e-8)
    tr = tr.clip(lower=1e-8)
    te = te.clip(lower=1e-8)
    return float(((tr - te) * np.log(tr / te)).sum())


def main() -> None:
    args = parse_args()
    args.out_tables_dir.mkdir(parents=True, exist_ok=True)
    args.out_report.parent.mkdir(parents=True, exist_ok=True)

    meta_prefix = [
        "source_dataset",
        "source_domain",
        "run_id",
        "group_id",
        "leakage_group",
        "target_binary",
        "target_family",
        "target_multiclass",
        "target_multiclass_detailed",
        "target_multiclass_attack_only",
        "is_attack_true",
        "attack_presence",
        "attack_type",
        "attack_family",
        "attack_protocol",
        "attack_subtype",
        "device",
        "device_is_explicit",
        "device_protocol_group",
        "network_protocol_group",
        "split",
        "source_file",
        "source_path",
    ]

    header_cols = pd.read_csv(args.train_path, nrows=0).columns.tolist()
    feature_cols = [c for c in header_cols if c not in meta_prefix]
    eval_feats = [c for c in KEY_FEATURES if c in feature_cols]

    # incremental stats
    n_total = 0
    n_attack = 0
    n_benign = 0
    split_rows = {"train": 0, "test": 0}

    class_counts = {}
    family_counts = {}
    device_counts = {}
    protocol_counts = {}

    # run-level accumulators for attack rows only
    run_sum = {}
    run_count = {}
    run_meta = {}

    # sampling for quantiles/correlation/drift
    samples = {"train": [], "test": []}
    sample_counts = {"train": 0, "test": 0}

    def process_file(path: Path, split_name: str) -> None:
        nonlocal n_total, n_attack, n_benign
        for chunk in pd.read_csv(path, chunksize=args.chunk_size, low_memory=False):
            n = len(chunk)
            n_total += n
            split_rows[split_name] += n
            y = pd.to_numeric(chunk["target_binary"], errors="coerce").fillna(0).astype(int)
            n_attack += int((y == 1).sum())
            n_benign += int((y == 0).sum())

            for k, v in chunk["target_binary"].value_counts().items():
                class_counts[str(k)] = class_counts.get(str(k), 0) + int(v)
            for k, v in chunk["target_family"].astype(str).value_counts().items():
                family_counts[k] = family_counts.get(k, 0) + int(v)
            for k, v in chunk["device"].astype(str).value_counts().items():
                device_counts[k] = device_counts.get(k, 0) + int(v)
            for k, v in chunk["network_protocol_group"].astype(str).value_counts().items():
                protocol_counts[k] = protocol_counts.get(k, 0) + int(v)

            # attack entity aggregation
            atk = chunk[y == 1]
            if not atk.empty:
                g = atk.groupby("run_id", sort=False)
                sums = g[eval_feats].sum(numeric_only=True)
                cnts = g.size()
                for run_id, row in sums.iterrows():
                    vals = row.to_numpy(dtype=float)
                    if run_id in run_sum:
                        run_sum[run_id] = run_sum[run_id] + vals
                        run_count[run_id] += int(cnts.loc[run_id])
                    else:
                        run_sum[run_id] = vals
                        run_count[run_id] = int(cnts.loc[run_id])
                rmeta = atk.groupby("run_id", as_index=False).agg(
                    attack_type=("attack_type", "first"),
                    attack_family=("attack_family", "first"),
                    attack_protocol=("attack_protocol", "first"),
                    network_protocol_group=("network_protocol_group", "first"),
                    source_file=("source_file", "first"),
                    source_path=("source_path", "first"),
                )
                for _, r in rmeta.iterrows():
                    run_meta[r["run_id"]] = r.to_dict()

            # deterministic sample
            if sample_counts[split_name] < args.sample_max_rows:
                frac = args.sample_frac
                smp = chunk.sample(frac=frac, random_state=42) if frac < 1.0 else chunk.copy()
                need = args.sample_max_rows - sample_counts[split_name]
                if len(smp) > need:
                    smp = smp.head(need)
                if not smp.empty:
                    samples[split_name].append(smp)
                    sample_counts[split_name] += len(smp)

    process_file(args.train_path, "train")
    process_file(args.test_path, "test")

    # build outputs
    inv = pd.read_csv(args.inventory_path)
    atk_inv = inv[(inv["source_domain"] == "attacks") & (inv["is_attack_true"] == 1)].copy()
    benign_inv = inv[(inv["target_binary"] == 0)].copy()

    # run entity table
    run_rows = []
    for run_id, s in run_sum.items():
        c = run_count[run_id]
        means = s / max(c, 1)
        row = {"run_id": run_id, "rows": c}
        row.update(run_meta.get(run_id, {}))
        for i, f in enumerate(eval_feats):
            row[f"mean_{f}"] = means[i]
        run_rows.append(row)
    run_df = pd.DataFrame(run_rows)
    run_df = run_df.sort_values("rows", ascending=False)

    type_entity = (
        run_df.groupby(["attack_type", "attack_family", "attack_protocol", "network_protocol_group"], as_index=False)
        .agg(
            runs=("run_id", "nunique"),
            total_rows=("rows", "sum"),
            mean_rows_per_run=("rows", "mean"),
            std_rows_per_run=("rows", "std"),
            min_rows_per_run=("rows", "min"),
            max_rows_per_run=("rows", "max"),
        )
        .sort_values(["runs", "total_rows"], ascending=[False, False])
    )
    type_entity["rows_per_run_cv"] = (
        type_entity["std_rows_per_run"].fillna(0.0) / type_entity["mean_rows_per_run"].replace(0, np.nan)
    ).fillna(0.0)

    # train-test drift on sampled data
    train_s = pd.concat(samples["train"], ignore_index=True) if samples["train"] else pd.DataFrame()
    test_s = pd.concat(samples["test"], ignore_index=True) if samples["test"] else pd.DataFrame()

    drift_rows = []
    if not train_s.empty and not test_s.empty:
        for f in eval_feats:
            psi = _psi(train_s[f], test_s[f], bins=10)
            drift_rows.append({"feature": f, "psi": psi})
    drift_df = pd.DataFrame(drift_rows).sort_values("psi", ascending=False)

    # simple similarity between attack runs
    pair_df = pd.DataFrame()
    if len(run_df) > 1 and eval_feats:
        mat = run_df[[f"mean_{f}" for f in eval_feats]].to_numpy(dtype=float)
        mu = np.nanmean(mat, axis=0)
        sd = np.nanstd(mat, axis=0)
        sd = np.where(sd == 0, 1.0, sd)
        z = (mat - mu) / sd
        pairs = []
        for i, j in combinations(range(len(run_df)), 2):
            d = float(np.linalg.norm(z[i] - z[j]))
            pairs.append(
                {
                    "run_a": run_df.iloc[i]["run_id"],
                    "run_b": run_df.iloc[j]["run_id"],
                    "attack_type_a": run_df.iloc[i]["attack_type"],
                    "attack_type_b": run_df.iloc[j]["attack_type"],
                    "distance_z": d,
                }
            )
        pair_df = pd.DataFrame(pairs).sort_values("distance_z", ascending=True).head(50)

    # save tables
    overview = pd.DataFrame(
        [
            {"metric": "rows_total", "value": n_total},
            {"metric": "rows_train", "value": split_rows["train"]},
            {"metric": "rows_test", "value": split_rows["test"]},
            {"metric": "rows_attack", "value": n_attack},
            {"metric": "rows_benign", "value": n_benign},
            {"metric": "attack_runs", "value": int(run_df["run_id"].nunique())},
            {"metric": "attack_types", "value": int(run_df["attack_type"].nunique())},
            {"metric": "attack_types_multi_run", "value": int((type_entity["runs"] > 1).sum())},
            {"metric": "attack_types_single_run", "value": int((type_entity["runs"] == 1).sum())},
            {"metric": "profiling_files", "value": int((inv["source_domain"] == "profiling").sum())},
        ]
    )
    overview.to_csv(args.out_tables_dir / "overview.csv", index=False)
    pd.DataFrame(sorted(class_counts.items()), columns=["target_binary", "rows"]).to_csv(
        args.out_tables_dir / "class_balance.csv", index=False
    )
    pd.DataFrame(sorted(family_counts.items(), key=lambda kv: -kv[1]), columns=["target_family", "rows"]).to_csv(
        args.out_tables_dir / "family_balance.csv", index=False
    )
    pd.DataFrame(sorted(protocol_counts.items(), key=lambda kv: -kv[1]), columns=["network_protocol_group", "rows"]).to_csv(
        args.out_tables_dir / "protocol_balance.csv", index=False
    )
    pd.DataFrame(sorted(device_counts.items(), key=lambda kv: -kv[1]), columns=["device", "rows"]).to_csv(
        args.out_tables_dir / "device_balance.csv", index=False
    )
    atk_inv.to_csv(args.out_tables_dir / "attack_file_inventory.csv", index=False)
    benign_inv.to_csv(args.out_tables_dir / "benign_file_inventory.csv", index=False)
    run_df.to_csv(args.out_tables_dir / "attack_run_entity_features.csv", index=False)
    type_entity.to_csv(args.out_tables_dir / "attack_type_entity_summary.csv", index=False)
    drift_df.to_csv(args.out_tables_dir / "train_test_feature_drift_psi.csv", index=False)
    pair_df.to_csv(args.out_tables_dir / "closest_attack_run_pairs.csv", index=False)

    # report
    run_desc = run_df["rows"].describe(percentiles=[0.1, 0.25, 0.5, 0.75, 0.9]).to_dict()
    lines = [
        "# Advanced EDA Summary",
        "",
        f"- Total rows: **{n_total:,}**",
        f"- Train rows: **{split_rows['train']:,}**",
        f"- Test rows: **{split_rows['test']:,}**",
        f"- Attack rows: **{n_attack:,}**",
        f"- Benign rows: **{n_benign:,}**",
        "",
        "## Attack Entity View (Run-Level)",
        "",
        "- Entity definition: one attack run/capture file (`run_id`).",
        f"- Attack runs: **{int(run_df['run_id'].nunique())}**",
        f"- Attack types: **{int(run_df['attack_type'].nunique())}**",
        f"- Multi-run attack types: **{int((type_entity['runs'] > 1).sum())}**",
        f"- Single-run attack types: **{int((type_entity['runs'] == 1).sum())}**",
        "",
        "### Rows Per Attack Run",
        f"- min: {run_desc.get('min', np.nan):,.0f}",
        f"- 10%: {run_desc.get('10%', np.nan):,.0f}",
        f"- 25%: {run_desc.get('25%', np.nan):,.0f}",
        f"- median: {run_desc.get('50%', np.nan):,.0f}",
        f"- 75%: {run_desc.get('75%', np.nan):,.0f}",
        f"- 90%: {run_desc.get('90%', np.nan):,.0f}",
        f"- max: {run_desc.get('max', np.nan):,.0f}",
        "",
        "## Train/Test Drift (PSI, sample-based)",
        "",
    ]
    if drift_df.empty:
        lines.append("- Drift could not be computed (insufficient sampled data).")
    else:
        for _, r in drift_df.head(10).iterrows():
            lines.append(f"- `{r['feature']}`: PSI={r['psi']:.4f}")

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Rows are flow/windows; attacks should be interpreted at both row-level and run-level.",
            "- Run-level tables are in `attack_run_entity_features.csv` and `attack_type_entity_summary.csv`.",
            "- Use `leakage_group`/`group_id` for grouped CV to avoid splitting one run across folds.",
        ]
    )

    args.out_report.write_text("\n".join(lines), encoding="utf-8")

    print(f"WROTE_TABLES={args.out_tables_dir}")
    print(f"WROTE_REPORT={args.out_report}")


if __name__ == "__main__":
    main()
