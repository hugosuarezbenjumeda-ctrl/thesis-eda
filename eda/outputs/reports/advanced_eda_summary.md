# Advanced EDA Summary

- Total rows: **9,320,056**
- Train rows: **7,595,887**
- Test rows: **1,724,169**
- Attack rows: **8,669,685**
- Benign rows: **650,371**

## Attack Entity View (Run-Level)

- Entity definition: one attack run/capture file (`run_id`).
- Attack runs: **72**
- Attack types: **57**
- Multi-run attack types: **15**
- Single-run attack types: **42**

### Rows Per Attack Run
- min: 186
- 10%: 3,964
- 25%: 43,761
- median: 124,329
- 75%: 195,197
- 90%: 204,034
- max: 207,295

## Train/Test Drift (PSI, sample-based)

- `IAT`: PSI=3.5099
- `Rate`: PSI=0.1860
- `Srate`: PSI=0.1860
- `Std`: PSI=0.0210
- `Max`: PSI=0.0105
- `AVG`: PSI=0.0100
- `Tot sum`: PSI=0.0086
- `Min`: PSI=0.0057
- `TCP`: PSI=0.0010
- `Weight`: PSI=0.0001

## Notes

- Rows are flow/windows; attacks should be interpreted at both row-level and run-level.
- Run-level tables are in `attack_run_entity_features.csv` and `attack_type_entity_summary.csv`.
- Use `leakage_group`/`group_id` for grouped CV to avoid splitting one run across folds.