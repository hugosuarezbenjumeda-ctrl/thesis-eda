# EDA Workspace Structure

This folder layout is designed to keep your exploratory data analysis (EDA) organized and reproducible.

## Tree

```text
eda/
├── data/
│   ├── raw/                  # Original data dumps (never edit)
│   ├── interim/              # Temporary cleaned/merged datasets
│   ├── processed/            # Final analysis-ready datasets
│   └── external/             # Third-party or reference datasets
├── notebooks/
│   ├── 01_data_overview/     # Schema checks, first-pass profiling
│   ├── 02_cleaning/          # Missing values, type fixes, outlier handling
│   ├── 03_univariate_analysis/
│   ├── 04_bivariate_analysis/
│   └── 05_feature_engineering/
├── src/
│   ├── config/               # Config files/constants for paths and settings
│   ├── utils/                # Reusable helpers (I/O, plotting, stats)
│   ├── visualization/        # Reusable plotting functions/themes
│   └── profiling/            # Data quality/profiling scripts
├── outputs/
│   ├── figures/              # Exported charts
│   ├── tables/               # Summary and model tables
│   └── reports/              # Slide decks, markdown/html summaries
├── logs/                     # Run logs from scripts or notebooks
└── references/               # Data dictionaries, business rules, notes
```

## Suggested workflow

1. Put untouched source files in `data/raw/`.
2. Use notebooks in numbered order under `notebooks/`.
3. Move reusable notebook code into `src/`.
4. Save artifacts to `outputs/` so results are easy to share.

## Bluetooth PCAP to CSV (CICIoMT schema)

To align Bluetooth data with the WiFi/MQTT CSV schema, use:

`eda/src/profiling/pcap_to_ciciomt_csv.py`

Requirements:
- `python`
- `pandas`
- `numpy`
- `tshark` (Wireshark CLI, must be in `PATH`)

Example: convert Bluetooth PCAPs directly from the tar archive:

```powershell
python eda/src/profiling/pcap_to_ciciomt_csv.py `
  --tar-file eda/data/raw/CICIoMT2024.tar `
  --member-prefix Bluetooth/ `
  --output-root eda/data/interim/CICIoMT2024 `
  --window-size 10
```

Example: convert from an already extracted folder:

```powershell
python eda/src/profiling/pcap_to_ciciomt_csv.py `
  --input-root eda/data/interim/CICIoMT2024 `
  --output-root eda/data/interim/CICIoMT2024 `
  --window-size 10
```

Output paths mirror the dataset layout and replace `pcap/` with `csv/` or `CSV/`,
then append `.csv` (for example: `Bluetooth/attacks/csv/train/*.pcap.csv`).
