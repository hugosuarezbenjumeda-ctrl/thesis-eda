#!/usr/bin/env python
"""Organize generated CSV artifacts into `eda/actual eda` and build a PDF report."""

from __future__ import annotations

import shutil
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import pandas as pd


def safe_move(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        if dst.is_file():
            dst.unlink()
        else:
            shutil.rmtree(dst)
    shutil.move(str(src), str(dst))


def load_or_empty(path: Path) -> pd.DataFrame:
    return pd.read_csv(path) if path.exists() else pd.DataFrame()


def main() -> None:
    root = Path("eda")
    actual = root / "actual eda"
    csv_root = actual / "csv"
    figs_dir = actual / "figures"
    report_dir = actual / "report"
    figs_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    move_files = [
        (root / "data" / "joined" / "attacks_train_joined.csv", csv_root / "joined" / "attacks_train_joined.csv"),
        (root / "data" / "joined" / "attacks_test_joined.csv", csv_root / "joined" / "attacks_test_joined.csv"),
        (root / "data" / "joined" / "attacks_file_inventory.csv", csv_root / "joined" / "attacks_file_inventory.csv"),
        (root / "data" / "joined" / "attacks_joined_summary.csv", csv_root / "joined" / "attacks_joined_summary.csv"),
        (root / "data" / "joined" / "attacks_header_mismatches.csv", csv_root / "joined" / "attacks_header_mismatches.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "overview.csv", csv_root / "advanced_eda" / "overview.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "class_balance.csv", csv_root / "advanced_eda" / "class_balance.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "family_balance.csv", csv_root / "advanced_eda" / "family_balance.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "protocol_balance.csv", csv_root / "advanced_eda" / "protocol_balance.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "device_balance.csv", csv_root / "advanced_eda" / "device_balance.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "attack_type_entity_summary.csv", csv_root / "advanced_eda" / "attack_type_entity_summary.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "train_test_feature_drift_psi.csv", csv_root / "advanced_eda" / "train_test_feature_drift_psi.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "attack_run_entity_features.csv", csv_root / "advanced_eda" / "attack_run_entity_features.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "closest_attack_run_pairs.csv", csv_root / "advanced_eda" / "closest_attack_run_pairs.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "attack_file_inventory.csv", csv_root / "advanced_eda" / "attack_file_inventory.csv"),
        (root / "outputs" / "tables" / "advanced_eda" / "benign_file_inventory.csv", csv_root / "advanced_eda" / "benign_file_inventory.csv"),
        (root / "outputs" / "tables" / "attack_hierarchy_eda" / "attack_rows_per_run_distribution.csv", csv_root / "attack_hierarchy_eda" / "attack_rows_per_run_distribution.csv"),
        (root / "outputs" / "tables" / "attack_hierarchy_eda" / "attack_runs_rows.csv", csv_root / "attack_hierarchy_eda" / "attack_runs_rows.csv"),
        (root / "outputs" / "tables" / "attack_hierarchy_eda" / "attack_run_inventory.csv", csv_root / "attack_hierarchy_eda" / "attack_run_inventory.csv"),
        (root / "outputs" / "tables" / "attack_hierarchy_eda" / "attack_type_by_split_summary.csv", csv_root / "attack_hierarchy_eda" / "attack_type_by_split_summary.csv"),
        (root / "outputs" / "tables" / "attack_hierarchy_eda" / "attack_type_runs_summary.csv", csv_root / "attack_hierarchy_eda" / "attack_type_runs_summary.csv"),
        (root / "outputs" / "tables" / "attack_hierarchy_eda" / "attack_type_summary.csv", csv_root / "attack_hierarchy_eda" / "attack_type_summary.csv"),
    ]

    moved = []
    for src, dst in move_files:
        if src.exists():
            safe_move(src, dst)
            moved.append(dst)

    # Load main tables from new location
    overview = load_or_empty(csv_root / "advanced_eda" / "overview.csv")
    class_bal = load_or_empty(csv_root / "advanced_eda" / "class_balance.csv")
    fam_bal = load_or_empty(csv_root / "advanced_eda" / "family_balance.csv")
    proto_bal = load_or_empty(csv_root / "advanced_eda" / "protocol_balance.csv")
    drift = load_or_empty(csv_root / "advanced_eda" / "train_test_feature_drift_psi.csv")
    type_runs = load_or_empty(csv_root / "attack_hierarchy_eda" / "attack_type_runs_summary.csv")
    run_dist = load_or_empty(csv_root / "attack_hierarchy_eda" / "attack_rows_per_run_distribution.csv")

    pdf_path = report_dir / "actual_eda_report.pdf"
    with PdfPages(pdf_path) as pdf:
        # Page 1: headline metrics
        fig = plt.figure(figsize=(11.7, 8.3))
        plt.axis("off")
        lines = ["Actual EDA Report", ""]
        if not overview.empty:
            for _, r in overview.iterrows():
                lines.append(f"{r['metric']}: {r['value']}")
        else:
            lines.append("Overview table not found.")
        lines += ["", f"CSV artifacts moved: {len(moved)}", f"Output root: {actual}"]
        fig.text(0.06, 0.94, "\n".join(lines), va="top", fontsize=12, family="monospace")
        pdf.savefig(fig, bbox_inches="tight")
        plt.close(fig)

        # Page 2: class balance
        if not class_bal.empty:
            fig, ax = plt.subplots(figsize=(11.7, 8.3))
            x = class_bal.iloc[:, 0].astype(str)
            y = class_bal.iloc[:, 1].astype(float)
            ax.bar(x, y)
            ax.set_title("Class Balance (target_binary)")
            ax.set_ylabel("Rows")
            pdf.savefig(fig, bbox_inches="tight")
            fig.savefig(figs_dir / "class_balance.png", dpi=160)
            plt.close(fig)

        # Page 3: attack family distribution
        if not fam_bal.empty:
            top = fam_bal.head(10).copy()
            fig, ax = plt.subplots(figsize=(11.7, 8.3))
            ax.barh(top.iloc[::-1, 0], top.iloc[::-1, 1].astype(float))
            ax.set_title("Top Attack Families by Rows")
            ax.set_xlabel("Rows")
            pdf.savefig(fig, bbox_inches="tight")
            fig.savefig(figs_dir / "attack_family_top.png", dpi=160)
            plt.close(fig)

        # Page 4: protocol group distribution
        if not proto_bal.empty:
            fig, ax = plt.subplots(figsize=(11.7, 8.3))
            ax.bar(proto_bal.iloc[:, 0].astype(str), proto_bal.iloc[:, 1].astype(float))
            ax.set_title("Rows by Network Protocol Group")
            ax.set_ylabel("Rows")
            pdf.savefig(fig, bbox_inches="tight")
            fig.savefig(figs_dir / "protocol_group_balance.png", dpi=160)
            plt.close(fig)

        # Page 5: top attack types by total rows
        if not type_runs.empty:
            top = type_runs.sort_values("total_rows", ascending=False).head(15)
            fig, ax = plt.subplots(figsize=(11.7, 8.3))
            ax.barh(top.iloc[::-1]["attack_type"], top.iloc[::-1]["total_rows"].astype(float))
            ax.set_title("Top Attack Types by Total Rows")
            ax.set_xlabel("Rows")
            pdf.savefig(fig, bbox_inches="tight")
            fig.savefig(figs_dir / "top_attack_types_rows.png", dpi=160)
            plt.close(fig)

            fig, ax = plt.subplots(figsize=(11.7, 8.3))
            top_runs = type_runs.sort_values("runs", ascending=False).head(20)
            ax.barh(top_runs.iloc[::-1]["attack_type"], top_runs.iloc[::-1]["runs"].astype(float))
            ax.set_title("Attack Types by Number of Runs (Entities)")
            ax.set_xlabel("Runs")
            pdf.savefig(fig, bbox_inches="tight")
            fig.savefig(figs_dir / "attack_type_runs.png", dpi=160)
            plt.close(fig)

        # Page 6: drift PSI
        if not drift.empty:
            top = drift.sort_values("psi", ascending=False).head(12)
            fig, ax = plt.subplots(figsize=(11.7, 8.3))
            ax.barh(top.iloc[::-1]["feature"], top.iloc[::-1]["psi"].astype(float))
            ax.set_title("Top Train/Test Drift Features (PSI)")
            ax.set_xlabel("PSI")
            pdf.savefig(fig, bbox_inches="tight")
            fig.savefig(figs_dir / "train_test_drift_psi.png", dpi=160)
            plt.close(fig)

        # Page 7: rows-per-run distribution
        if not run_dist.empty:
            # The file may have an unnamed index column
            if run_dist.columns[0].startswith("Unnamed") or run_dist.columns[0] == "":
                run_dist = run_dist.rename(columns={run_dist.columns[0]: "stat"})
            elif run_dist.columns[0] != "stat":
                run_dist = run_dist.rename(columns={run_dist.columns[0]: "stat"})
            col = [c for c in run_dist.columns if c != "stat"][0]
            keep = run_dist[run_dist["stat"].isin(["min", "10%", "25%", "50%", "75%", "90%", "95%", "99%", "max"])]
            fig, ax = plt.subplots(figsize=(11.7, 8.3))
            ax.plot(keep["stat"], keep[col].astype(float), marker="o")
            ax.set_title("Rows per Attack Run Distribution")
            ax.set_ylabel("Rows")
            pdf.savefig(fig, bbox_inches="tight")
            fig.savefig(figs_dir / "rows_per_run_distribution.png", dpi=160)
            plt.close(fig)

        # Last page: artifact list
        fig = plt.figure(figsize=(11.7, 8.3))
        plt.axis("off")
        art_lines = ["CSV Artifacts Included", ""]
        for p in sorted(moved):
            size_mb = p.stat().st_size / (1024 * 1024)
            art_lines.append(f"{p.as_posix()}  ({size_mb:.2f} MB)")
        fig.text(0.04, 0.96, "\n".join(art_lines), va="top", fontsize=9, family="monospace")
        pdf.savefig(fig, bbox_inches="tight")
        plt.close(fig)

    print(f"MOVED_CSV_COUNT={len(moved)}")
    print(f"ACTUAL_EDA_DIR={actual}")
    print(f"PDF_REPORT={pdf_path}")
    print(f"FIGURES_DIR={figs_dir}")


if __name__ == "__main__":
    main()
