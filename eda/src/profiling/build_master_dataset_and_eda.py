#!/usr/bin/env python
"""Build a master CICIoMT CSV and generate EDA artifacts.

This script merges all CSV files under a dataset root into one master CSV while
adding metadata columns required for downstream analysis.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path, PurePosixPath

import numpy as np
import pandas as pd


SCENARIO_TOKENS = {
    "LAN",
    "WAN",
    "MIC",
    "WATCH",
    "PHOTO",
    "RECORDING",
    "PRECORDING",
    "APP",
    "PHYSICAL",
    "POWER",
    "EMERGENCY",
}

METADATA_COLUMNS = [
    "is_attack",
    "attack_label",
    "profile",
    "device_profile",
    "scenario",
    "protocol_group",
    "data_category",
    "split",
    "source_file",
    "source_path",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge CICIoMT CSV files and generate EDA summary tables."
    )
    parser.add_argument(
        "--input-root",
        type=Path,
        default=Path("eda/data/interim/CICIoMT2024"),
        help="Root folder containing CSV files to merge.",
    )
    parser.add_argument(
        "--master-output",
        type=Path,
        default=Path("eda/data/processed/ciciomt_master_profiles.csv"),
        help="Output path for merged master CSV.",
    )
    parser.add_argument(
        "--tables-dir",
        type=Path,
        default=Path("eda/outputs/tables/master_eda"),
        help="Directory for EDA summary tables.",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=Path("eda/outputs/reports/master_eda_summary.md"),
        help="Output markdown report path.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=200_000,
        help="Rows per chunk while merging CSVs.",
    )
    return parser.parse_args()


def discover_csv_files(input_root: Path) -> list[Path]:
    files = [
        p
        for p in input_root.rglob("*.csv")
        if p.is_file() and p.relative_to(input_root).parts[0] in {"Bluetooth", "WiFI_and_MQTT"}
    ]
    return sorted(files)


def parse_profile_metadata(profile: str, data_category: str) -> tuple[str, str]:
    if data_category != "profiling":
        return "N/A", "N/A"
    tokens = profile.split("_")
    scenario_idx = None
    for i, tok in enumerate(tokens):
        if tok.upper() in SCENARIO_TOKENS:
            scenario_idx = i
            break
    if scenario_idx is None:
        return profile, "N/A"
    device = "_".join(tokens[:scenario_idx]) if scenario_idx > 0 else profile
    scenario = "_".join(tokens[scenario_idx:])
    return (device if device else profile, scenario if scenario else "N/A")


def metadata_from_relative_path(rel: PurePosixPath) -> dict[str, object]:
    parts = rel.parts
    lower_parts = [p.lower() for p in parts]
    source_file = parts[-1]
    profile = source_file.replace(".pcap.csv", "").replace(".csv", "")
    protocol_group = parts[0]
    data_category = "attacks" if "attacks" in lower_parts else "profiling"
    split = "profiling"
    if "train" in lower_parts:
        split = "train"
    elif "test" in lower_parts:
        split = "test"

    if data_category == "attacks":
        attack_label = re.sub(r"_(train|test)$", "", profile, flags=re.IGNORECASE)
        is_attack = 0 if "benign" in attack_label.lower() else 1
    else:
        attack_label = "Benign_Profile"
        is_attack = 0

    device_profile, scenario = parse_profile_metadata(profile, data_category)
    return {
        "is_attack": int(is_attack),
        "attack_label": attack_label,
        "profile": profile,
        "device_profile": device_profile,
        "scenario": scenario,
        "protocol_group": protocol_group,
        "data_category": data_category,
        "split": split,
        "source_file": source_file,
        "source_path": rel.as_posix(),
    }


def counter_to_df(counter: Counter, key_col: str, value_col: str = "rows") -> pd.DataFrame:
    df = pd.DataFrame({key_col: list(counter.keys()), value_col: list(counter.values())})
    df = df.sort_values(value_col, ascending=False).reset_index(drop=True)
    total = df[value_col].sum()
    if total > 0:
        df["pct"] = (df[value_col] / total * 100.0).round(4)
    else:
        df["pct"] = 0.0
    return df


def build_master_and_eda(
    input_root: Path,
    master_output: Path,
    tables_dir: Path,
    report_path: Path,
    chunk_size: int,
) -> None:
    csv_files = discover_csv_files(input_root)
    if not csv_files:
        raise RuntimeError(f"No CSV files found under {input_root}")

    master_output.parent.mkdir(parents=True, exist_ok=True)
    tables_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    if master_output.exists():
        master_output.unlink()

    feature_cols: list[str] | None = None
    first_write = True

    total_rows = 0
    total_files = 0
    class_counts: Counter = Counter()
    split_counts: Counter = Counter()
    protocol_counts: Counter = Counter()
    attack_label_counts: Counter = Counter()
    profile_counts: Counter = Counter()
    category_counts: Counter = Counter()

    file_inventory: list[dict[str, object]] = []
    header_mismatches: list[dict[str, object]] = []

    missing_counts: pd.Series | None = None
    num_counts: pd.Series | None = None
    num_sums: pd.Series | None = None
    num_sumsq: pd.Series | None = None
    num_min: pd.Series | None = None
    num_max: pd.Series | None = None

    for file_path in csv_files:
        rel = PurePosixPath(file_path.relative_to(input_root).as_posix())
        meta = metadata_from_relative_path(rel)
        total_files += 1
        file_rows = 0

        for chunk in pd.read_csv(file_path, chunksize=chunk_size, low_memory=False):
            chunk_cols = list(chunk.columns)
            if feature_cols is None:
                feature_cols = chunk_cols
                missing_counts = pd.Series(0, index=feature_cols, dtype="int64")
                num_counts = pd.Series(0.0, index=feature_cols, dtype="float64")
                num_sums = pd.Series(0.0, index=feature_cols, dtype="float64")
                num_sumsq = pd.Series(0.0, index=feature_cols, dtype="float64")
                num_min = pd.Series(np.inf, index=feature_cols, dtype="float64")
                num_max = pd.Series(-np.inf, index=feature_cols, dtype="float64")
            elif chunk_cols != feature_cols:
                header_mismatches.append(
                    {
                        "source_path": rel.as_posix(),
                        "expected_columns": "|".join(feature_cols),
                        "found_columns": "|".join(chunk_cols),
                    }
                )
                continue

            assert feature_cols is not None
            assert missing_counts is not None
            assert num_counts is not None
            assert num_sums is not None
            assert num_sumsq is not None
            assert num_min is not None
            assert num_max is not None

            enriched = chunk.copy()
            for k, v in meta.items():
                enriched[k] = v
            enriched = enriched[METADATA_COLUMNS + feature_cols]
            enriched.to_csv(master_output, mode="w" if first_write else "a", index=False, header=first_write)
            first_write = False

            rows = len(chunk)
            file_rows += rows
            total_rows += rows

            class_counts[str(meta["is_attack"])] += rows
            split_counts[str(meta["split"])] += rows
            protocol_counts[str(meta["protocol_group"])] += rows
            attack_label_counts[str(meta["attack_label"])] += rows
            profile_counts[str(meta["profile"])] += rows
            category_counts[str(meta["data_category"])] += rows

            missing_counts += chunk[feature_cols].isna().sum()

            numeric_chunk = chunk[feature_cols].apply(pd.to_numeric, errors="coerce")
            num_counts += numeric_chunk.count()
            num_sums += numeric_chunk.sum(skipna=True)
            num_sumsq += (numeric_chunk * numeric_chunk).sum(skipna=True)

            cmin = numeric_chunk.min(skipna=True)
            cmax = numeric_chunk.max(skipna=True)
            for col in feature_cols:
                vmin = cmin[col]
                vmax = cmax[col]
                if pd.notna(vmin) and vmin < num_min[col]:
                    num_min[col] = float(vmin)
                if pd.notna(vmax) and vmax > num_max[col]:
                    num_max[col] = float(vmax)

        file_inventory.append(
            {
                "source_path": rel.as_posix(),
                "rows": file_rows,
                "is_attack": meta["is_attack"],
                "attack_label": meta["attack_label"],
                "profile": meta["profile"],
                "device_profile": meta["device_profile"],
                "scenario": meta["scenario"],
                "protocol_group": meta["protocol_group"],
                "data_category": meta["data_category"],
                "split": meta["split"],
            }
        )

    if total_rows == 0:
        raise RuntimeError("No rows were merged. Check source CSV files.")

    assert feature_cols is not None
    assert missing_counts is not None
    assert num_counts is not None
    assert num_sums is not None
    assert num_sumsq is not None
    assert num_min is not None
    assert num_max is not None

    inv_df = pd.DataFrame(file_inventory).sort_values("rows", ascending=False)
    inv_df.to_csv(tables_dir / "file_inventory.csv", index=False)

    if header_mismatches:
        pd.DataFrame(header_mismatches).to_csv(tables_dir / "header_mismatches.csv", index=False)
    else:
        pd.DataFrame(columns=["source_path", "expected_columns", "found_columns"]).to_csv(
            tables_dir / "header_mismatches.csv", index=False
        )

    class_df = counter_to_df(class_counts, "is_attack")
    split_df = counter_to_df(split_counts, "split")
    protocol_df = counter_to_df(protocol_counts, "protocol_group")
    category_df = counter_to_df(category_counts, "data_category")
    attack_df = counter_to_df(attack_label_counts, "attack_label")
    profile_df = counter_to_df(profile_counts, "profile")

    class_df.to_csv(tables_dir / "class_balance.csv", index=False)
    split_df.to_csv(tables_dir / "split_balance.csv", index=False)
    protocol_df.to_csv(tables_dir / "protocol_group_balance.csv", index=False)
    category_df.to_csv(tables_dir / "data_category_balance.csv", index=False)
    attack_df.to_csv(tables_dir / "attack_label_counts.csv", index=False)
    profile_df.to_csv(tables_dir / "profile_counts.csv", index=False)

    missing_df = pd.DataFrame(
        {
            "column": feature_cols,
            "missing_count": missing_counts.reindex(feature_cols).astype("int64").values,
            "missing_pct": (missing_counts.reindex(feature_cols).values / total_rows * 100.0),
        }
    ).sort_values("missing_pct", ascending=False)
    missing_df.to_csv(tables_dir / "missing_summary.csv", index=False)

    mean = num_sums / num_counts.replace(0, np.nan)
    var = (num_sumsq / num_counts.replace(0, np.nan)) - (mean * mean)
    var = var.clip(lower=0)
    std = np.sqrt(var)

    numeric_summary = pd.DataFrame(
        {
            "column": feature_cols,
            "count": num_counts.reindex(feature_cols).values,
            "mean": mean.reindex(feature_cols).values,
            "std": std.reindex(feature_cols).values,
            "min": num_min.reindex(feature_cols).replace(np.inf, np.nan).values,
            "max": num_max.reindex(feature_cols).replace(-np.inf, np.nan).values,
        }
    )
    numeric_summary.to_csv(tables_dir / "numeric_summary.csv", index=False)

    master_size_bytes = master_output.stat().st_size
    overview = pd.DataFrame(
        [
            {"metric": "total_rows", "value": total_rows},
            {"metric": "total_columns", "value": len(METADATA_COLUMNS) + len(feature_cols)},
            {"metric": "feature_columns", "value": len(feature_cols)},
            {"metric": "metadata_columns", "value": len(METADATA_COLUMNS)},
            {"metric": "source_files", "value": total_files},
            {"metric": "master_size_bytes", "value": master_size_bytes},
            {"metric": "master_size_mb", "value": round(master_size_bytes / (1024 * 1024), 2)},
        ]
    )
    overview.to_csv(tables_dir / "dataset_overview.csv", index=False)

    top_profiles = profile_df.head(15)
    top_attacks = attack_df.head(15)

    lines = [
        "# Master Dataset EDA Summary",
        "",
        f"- Input root: `{input_root.as_posix()}`",
        f"- Master CSV: `{master_output.as_posix()}`",
        f"- Rows: **{total_rows:,}**",
        f"- Columns: **{len(METADATA_COLUMNS) + len(feature_cols)}** "
        f"({len(METADATA_COLUMNS)} metadata + {len(feature_cols)} features)",
        f"- Source files merged: **{total_files}**",
        f"- Master size: **{master_size_bytes / (1024 * 1024):.2f} MB**",
        "",
        "## Class Balance (`is_attack`)",
        "",
    ]
    for _, r in class_df.iterrows():
        lines.append(f"- `{int(r['is_attack'])}`: {int(r['rows']):,} rows ({r['pct']:.2f}%)")

    lines.extend(
        [
            "",
            "## Data Category Balance",
            "",
        ]
    )
    for _, r in category_df.iterrows():
        lines.append(f"- `{r['data_category']}`: {int(r['rows']):,} rows ({r['pct']:.2f}%)")

    lines.extend(
        [
            "",
            "## Split Balance",
            "",
        ]
    )
    for _, r in split_df.iterrows():
        lines.append(f"- `{r['split']}`: {int(r['rows']):,} rows ({r['pct']:.2f}%)")

    lines.extend(
        [
            "",
            "## Top Profiles by Rows",
            "",
        ]
    )
    for _, r in top_profiles.iterrows():
        lines.append(f"- `{r['profile']}`: {int(r['rows']):,} rows ({r['pct']:.2f}%)")

    lines.extend(
        [
            "",
            "## Top Attack Labels by Rows",
            "",
        ]
    )
    for _, r in top_attacks.iterrows():
        lines.append(f"- `{r['attack_label']}`: {int(r['rows']):,} rows ({r['pct']:.2f}%)")

    lines.extend(
        [
            "",
            "## Missing Values",
            "",
        ]
    )
    top_missing = missing_df.head(10)
    for _, r in top_missing.iterrows():
        lines.append(f"- `{r['column']}`: {int(r['missing_count']):,} missing ({r['missing_pct']:.4f}%)")

    report_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"MASTER_CSV={master_output}")
    print(f"EDA_TABLES_DIR={tables_dir}")
    print(f"EDA_REPORT={report_path}")
    print(f"TOTAL_ROWS={total_rows}")
    print(f"TOTAL_COLUMNS={len(METADATA_COLUMNS) + len(feature_cols)}")
    print(f"SOURCE_FILES={total_files}")


def main() -> None:
    args = parse_args()
    if args.chunk_size <= 0:
        raise ValueError("--chunk-size must be > 0")
    build_master_and_eda(
        input_root=args.input_root,
        master_output=args.master_output,
        tables_dir=args.tables_dir,
        report_path=args.report_path,
        chunk_size=args.chunk_size,
    )


if __name__ == "__main__":
    main()
