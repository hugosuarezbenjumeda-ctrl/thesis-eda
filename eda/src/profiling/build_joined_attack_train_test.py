#!/usr/bin/env python
"""Build train/test joined attack datasets with rich metadata columns."""

from __future__ import annotations

import argparse
import hashlib
import re
from collections import Counter
from pathlib import Path, PurePosixPath

import numpy as np
import pandas as pd


META_COLUMNS = [
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Join attack CSV files into train/test masters with metadata."
    )
    parser.add_argument(
        "--input-root",
        type=Path,
        default=Path("eda/data/interim/CICIoMT2024"),
        help="Root folder containing extracted CSV files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("eda/data/joined"),
        help="Output directory for joined train/test CSVs.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=200_000,
        help="CSV read chunk size.",
    )
    parser.add_argument(
        "--include-profiling",
        action="store_true",
        help="Also include profiling CSV rows and split them into train/test.",
    )
    parser.add_argument(
        "--profiling-train-ratio",
        type=float,
        default=0.8,
        help="Fraction of profiling rows assigned to train when --include-profiling is used.",
    )
    return parser.parse_args()


def discover_attack_csvs(input_root: Path) -> list[Path]:
    files: list[Path] = []
    for p in input_root.rglob("*.csv"):
        rel = p.relative_to(input_root).as_posix().lower()
        if "/attacks/csv/train/" in rel or "/attacks/csv/test/" in rel:
            files.append(p)
    return sorted(files)


def discover_profiling_csvs(input_root: Path) -> list[Path]:
    files: list[Path] = []
    for p in input_root.rglob("*.csv"):
        rel = p.relative_to(input_root).as_posix().lower()
        if "/profiling/csv/" in rel:
            files.append(p)
    return sorted(files)


def classify_attack_family(attack_type: str, is_attack_true: int) -> str:
    if is_attack_true == 0:
        return "Benign"
    a = attack_type.lower()
    if "ddos" in a:
        return "DDoS"
    if re.search(r"(^|[-_])dos($|[-_])", a):
        return "DoS"
    if "recon" in a:
        return "Recon"
    if "spoof" in a:
        return "Spoofing"
    if "mqtt" in a:
        return "MQTT"
    return "Other"


def infer_device_and_protocol(
    protocol_group: str,
    attack_type: str,
) -> tuple[str, int, str]:
    if attack_type.startswith("Bluetooth_"):
        return ("Bluetooth", 1, "Bluetooth")
    if protocol_group == "Bluetooth":
        return ("Bluetooth", 1, "Bluetooth")

    # WiFI_and_MQTT attack filenames generally encode attack type, not device.
    # Keep device explicitness truthful.
    return ("Unknown", 0, "WiFi/MQTT")


def infer_attack_subtype(attack_type: str, attack_family: str) -> str:
    if attack_family == "Benign":
        return "None"
    if attack_type.startswith("TCP_IP-"):
        return attack_type.replace("TCP_IP-", "", 1)
    if attack_type.startswith("MQTT-"):
        return attack_type.replace("MQTT-", "", 1)
    if attack_type.startswith("Recon-"):
        return attack_type.replace("Recon-", "", 1)
    if attack_type.startswith("Bluetooth_"):
        return attack_type.replace("Bluetooth_", "", 1)
    return attack_type


def infer_attack_protocol(
    attack_type: str,
    protocol_group: str,
    attack_family: str,
) -> str:
    if protocol_group == "Bluetooth":
        return "Bluetooth"
    if attack_type.startswith("MQTT-"):
        return "MQTT"
    if attack_type.startswith("TCP_IP-"):
        return "TCP_IP"
    if attack_type.startswith("ARP_") or attack_type.startswith("ARP-"):
        return "ARP"
    if attack_type.startswith("Recon-"):
        return "Recon/Mixed"
    if attack_family == "Benign":
        return "Unknown"
    return "Other"


def _device_from_profile(profile_name: str) -> str:
    scenario_tokens = {
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
    toks = profile_name.split("_")
    for i, t in enumerate(toks):
        if t.upper() in scenario_tokens:
            return "_".join(toks[:i]) if i > 0 else profile_name
    return profile_name


def metadata_from_relpath(rel: PurePosixPath) -> dict[str, object]:
    parts = rel.parts
    protocol_group = parts[0]
    split = "train" if "train" in [p.lower() for p in parts] else "test"

    source_file = parts[-1]
    stem = source_file.replace(".pcap.csv", "").replace(".csv", "")
    attack_type = re.sub(r"_(train|test)$", "", stem, flags=re.IGNORECASE)

    is_attack_true = 0 if "benign" in attack_type.lower() else 1
    attack_presence = "attack" if is_attack_true == 1 else "benign"
    attack_family = classify_attack_family(attack_type, is_attack_true)
    attack_subtype = infer_attack_subtype(attack_type, attack_family)
    attack_protocol = infer_attack_protocol(attack_type, protocol_group, attack_family)

    device, device_is_explicit, device_protocol_group = infer_device_and_protocol(
        protocol_group=protocol_group,
        attack_type=attack_type,
    )

    return {
        "source_dataset": "CICIoMT2024",
        "source_domain": "attacks",
        "run_id": source_file,
        "group_id": f"{protocol_group}::{source_file}",
        "leakage_group": f"{protocol_group}::{source_file}",
        "target_binary": int(is_attack_true),
        "target_family": attack_family,
        "target_multiclass": attack_type if is_attack_true == 1 else "Benign",
        "target_multiclass_detailed": attack_type,
        "target_multiclass_attack_only": attack_type if is_attack_true == 1 else "NotAttack",
        "is_attack_true": int(is_attack_true),
        "attack_presence": attack_presence,
        "attack_type": attack_type,
        "attack_family": attack_family,
        "attack_protocol": attack_protocol,
        "attack_subtype": attack_subtype,
        "device": device,
        "device_is_explicit": int(device_is_explicit),
        "device_protocol_group": device_protocol_group,
        "network_protocol_group": protocol_group,
        "split": split,
        "source_file": source_file,
        "source_path": rel.as_posix(),
    }


def profiling_metadata_from_relpath(rel: PurePosixPath) -> dict[str, object]:
    parts = rel.parts
    protocol_group = parts[0]
    source_file = parts[-1]
    profile = source_file.replace(".pcap.csv", "").replace(".csv", "")
    device = _device_from_profile(profile)

    return {
        "source_dataset": "CICIoMT2024",
        "source_domain": "profiling",
        "run_id": source_file,
        "group_id": f"{protocol_group}::{source_file}",
        "leakage_group": f"{protocol_group}::{source_file}",
        "target_binary": 0,
        "target_family": "Benign",
        "target_multiclass": "Benign",
        "target_multiclass_detailed": "Benign_Profile",
        "target_multiclass_attack_only": "NotAttack",
        "is_attack_true": 0,
        "attack_presence": "benign",
        "attack_type": "Benign_Profile",
        "attack_family": "Benign",
        "attack_protocol": "Bluetooth" if protocol_group == "Bluetooth" else "Profile_Mixed",
        "attack_subtype": "Profile",
        "device": device,
        "device_is_explicit": 1,
        "device_protocol_group": "Bluetooth" if protocol_group == "Bluetooth" else "WiFi/MQTT",
        "network_protocol_group": protocol_group,
        "split": "profiling",
        "source_file": source_file,
        "source_path": rel.as_posix(),
    }


def build_joined_sets(
    input_root: Path,
    output_dir: Path,
    chunk_size: int,
    include_profiling: bool,
    profiling_train_ratio: float,
) -> None:
    attack_files = discover_attack_csvs(input_root)
    if not attack_files:
        raise RuntimeError(f"No attack CSV files found under {input_root}")
    profiling_files = discover_profiling_csvs(input_root) if include_profiling else []

    output_dir.mkdir(parents=True, exist_ok=True)
    out_train = output_dir / "attacks_train_joined.csv"
    out_test = output_dir / "attacks_test_joined.csv"
    out_inventory = output_dir / "attacks_file_inventory.csv"
    out_summary = output_dir / "attacks_joined_summary.csv"

    for out_path in [out_train, out_test, out_inventory, out_summary]:
        if out_path.exists():
            out_path.unlink()

    feature_cols: list[str] | None = None
    wrote_train = False
    wrote_test = False

    rows_by_split: Counter = Counter()
    rows_by_is_attack: Counter = Counter()
    rows_by_attack_type: Counter = Counter()
    rows_by_attack_family: Counter = Counter()
    rows_by_protocol: Counter = Counter()
    rows_by_device: Counter = Counter()

    inventory_rows: list[dict[str, object]] = []
    bad_headers: list[dict[str, object]] = []

    for file_path in attack_files:
        rel = PurePosixPath(file_path.relative_to(input_root).as_posix())
        meta = metadata_from_relpath(rel)
        file_rows = 0

        for chunk in pd.read_csv(file_path, chunksize=chunk_size, low_memory=False):
            cols = list(chunk.columns)
            if feature_cols is None:
                feature_cols = cols
            elif cols != feature_cols:
                bad_headers.append(
                    {
                        "source_path": rel.as_posix(),
                        "expected_header": "|".join(feature_cols),
                        "found_header": "|".join(cols),
                    }
                )
                continue

            enriched = chunk.copy()
            for k, v in meta.items():
                enriched[k] = v
            enriched = enriched[META_COLUMNS + feature_cols]

            if meta["split"] == "train":
                enriched.to_csv(out_train, mode="a", index=False, header=not wrote_train)
                wrote_train = True
            else:
                enriched.to_csv(out_test, mode="a", index=False, header=not wrote_test)
                wrote_test = True

            rows = len(enriched)
            file_rows += rows
            rows_by_split[str(meta["split"])] += rows
            rows_by_is_attack[str(meta["is_attack_true"])] += rows
            rows_by_attack_type[str(meta["attack_type"])] += rows
            rows_by_attack_family[str(meta["attack_family"])] += rows
            rows_by_protocol[str(meta["network_protocol_group"])] += rows
            rows_by_device[str(meta["device"])] += rows

        inventory_rows.append(
            {
                **meta,
                "rows": file_rows,
            }
        )

    if include_profiling and profiling_files:
        for file_path in profiling_files:
            rel = PurePosixPath(file_path.relative_to(input_root).as_posix())
            meta = profiling_metadata_from_relpath(rel)
            file_train_rows = 0
            file_test_rows = 0

            seed = int(hashlib.md5(rel.as_posix().encode("utf-8")).hexdigest()[:8], 16)
            rng = np.random.default_rng(seed)

            for chunk in pd.read_csv(file_path, chunksize=chunk_size, low_memory=False):
                cols = list(chunk.columns)
                if feature_cols is None:
                    feature_cols = cols
                elif cols != feature_cols:
                    bad_headers.append(
                        {
                            "source_path": rel.as_posix(),
                            "expected_header": "|".join(feature_cols),
                            "found_header": "|".join(cols),
                        }
                    )
                    continue

                enriched = chunk.copy()
                for k, v in meta.items():
                    enriched[k] = v

                mask_train = rng.random(len(enriched)) < profiling_train_ratio
                train_part = enriched.loc[mask_train].copy()
                test_part = enriched.loc[~mask_train].copy()

                if not train_part.empty:
                    train_part["split"] = "train"
                    train_part = train_part[META_COLUMNS + feature_cols]
                    train_part.to_csv(out_train, mode="a", index=False, header=not wrote_train)
                    wrote_train = True

                    r = len(train_part)
                    file_train_rows += r
                    rows_by_split["train"] += r
                    rows_by_is_attack["0"] += r
                    rows_by_attack_type["Benign_Profile"] += r
                    rows_by_attack_family["Benign"] += r
                    rows_by_protocol[str(meta["network_protocol_group"])] += r
                    rows_by_device[str(meta["device"])] += r

                if not test_part.empty:
                    test_part["split"] = "test"
                    test_part = test_part[META_COLUMNS + feature_cols]
                    test_part.to_csv(out_test, mode="a", index=False, header=not wrote_test)
                    wrote_test = True

                    r = len(test_part)
                    file_test_rows += r
                    rows_by_split["test"] += r
                    rows_by_is_attack["0"] += r
                    rows_by_attack_type["Benign_Profile"] += r
                    rows_by_attack_family["Benign"] += r
                    rows_by_protocol[str(meta["network_protocol_group"])] += r
                    rows_by_device[str(meta["device"])] += r

            inventory_rows.append(
                {
                    **meta,
                    "rows": file_train_rows + file_test_rows,
                    "profiling_train_rows": file_train_rows,
                    "profiling_test_rows": file_test_rows,
                }
            )

    if not wrote_train or not wrote_test:
        raise RuntimeError("Train/test outputs were not both created. Check input data.")

    inv_df = pd.DataFrame(inventory_rows).sort_values(["split", "rows"], ascending=[True, False])
    inv_df.to_csv(out_inventory, index=False)

    summary_rows: list[dict[str, object]] = []
    for k, v in rows_by_split.items():
        summary_rows.append({"metric_group": "rows_by_split", "metric_key": k, "value": int(v)})
    for k, v in rows_by_is_attack.items():
        summary_rows.append({"metric_group": "rows_by_is_attack_true", "metric_key": k, "value": int(v)})
    for k, v in rows_by_attack_family.items():
        summary_rows.append({"metric_group": "rows_by_attack_family", "metric_key": k, "value": int(v)})
    for k, v in rows_by_protocol.items():
        summary_rows.append({"metric_group": "rows_by_protocol_group", "metric_key": k, "value": int(v)})
    for k, v in rows_by_device.items():
        summary_rows.append({"metric_group": "rows_by_device", "metric_key": k, "value": int(v)})
    for k, v in sorted(rows_by_attack_type.items(), key=lambda kv: (-kv[1], kv[0])):
        summary_rows.append({"metric_group": "rows_by_attack_type", "metric_key": k, "value": int(v)})

    summary_df = pd.DataFrame(summary_rows)
    summary_df.to_csv(out_summary, index=False)

    if bad_headers:
        pd.DataFrame(bad_headers).to_csv(output_dir / "attacks_header_mismatches.csv", index=False)
    else:
        pd.DataFrame(columns=["source_path", "expected_header", "found_header"]).to_csv(
            output_dir / "attacks_header_mismatches.csv", index=False
        )

    print(f"ATTACK_FILES={len(attack_files)}")
    print(f"PROFILING_FILES_INCLUDED={len(profiling_files)}")
    print(f"TRAIN_OUT={out_train}")
    print(f"TEST_OUT={out_test}")
    print(f"INVENTORY_OUT={out_inventory}")
    print(f"SUMMARY_OUT={out_summary}")
    print(f"TRAIN_ROWS={rows_by_split.get('train', 0)}")
    print(f"TEST_ROWS={rows_by_split.get('test', 0)}")
    print(f"ATTACK_TRUE_ROWS={rows_by_is_attack.get('1', 0)}")
    print(f"BENIGN_ROWS={rows_by_is_attack.get('0', 0)}")


def main() -> None:
    args = parse_args()
    if args.chunk_size <= 0:
        raise ValueError("--chunk-size must be > 0")
    if not (0.0 < args.profiling_train_ratio < 1.0):
        raise ValueError("--profiling-train-ratio must be in (0,1)")
    build_joined_sets(
        input_root=args.input_root,
        output_dir=args.output_dir,
        chunk_size=args.chunk_size,
        include_profiling=args.include_profiling,
        profiling_train_ratio=args.profiling_train_ratio,
    )


if __name__ == "__main__":
    main()
