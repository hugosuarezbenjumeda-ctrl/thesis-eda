# Attack Hierarchy EDA

- Attack rows (`is_attack_true=1`): **8,669,685**
- Unique attack types: **57**
- Unique attack runs/files: **72**
- Mean rows per run: **120,412**
- Median rows per run: **124,329**

## What A Row Means

- A row is one feature window/sample from a capture, not one full attack event.
- A run/capture is one source CSV file and contains many rows.
- Therefore a single attack type is represented by one or multiple runs, each with many rows.

## Rows Per Run Distribution (attacks only)

- min: 186 rows
- 10%: 3,964 rows
- 25%: 43,761 rows
- 50%: 124,329 rows
- 75%: 195,197 rows
- 90%: 204,034 rows
- 95%: 205,886 rows
- 99%: 206,804 rows
- max: 207,295 rows

## Top Attack Types By Number Of Runs

- `TCP_IP-DDoS-UDP1` (WiFI_and_MQTT): runs=2, splits=test,train, rows=411,824
- `TCP_IP-DDoS-ICMP2` (WiFI_and_MQTT): runs=2, splits=test,train, rows=390,510
- `TCP_IP-DDoS-UDP2` (WiFI_and_MQTT): runs=2, splits=test,train, rows=363,711
- `TCP_IP-DDoS-ICMP1` (WiFI_and_MQTT): runs=2, splits=test,train, rows=348,945
- `MQTT-DDoS-Connect_Flood` (WiFI_and_MQTT): runs=2, splits=test,train, rows=214,952
- `Bluetooth_DoS` (Bluetooth): runs=2, splits=test,train, rows=125,011
- `Recon-Port_Scan` (WiFI_and_MQTT): runs=2, splits=test,train, rows=106,603
- `MQTT-DoS-Publish_Flood` (WiFI_and_MQTT): runs=2, splits=test,train, rows=52,881
- `MQTT-DDoS-Publish_Flood` (WiFI_and_MQTT): runs=2, splits=test,train, rows=36,039
- `Recon-OS_Scan` (WiFI_and_MQTT): runs=2, splits=test,train, rows=20,666
- `ARP_Spoofing` (WiFI_and_MQTT): runs=2, splits=test,train, rows=17,791
- `MQTT-DoS-Connect_Flood` (WiFI_and_MQTT): runs=2, splits=test,train, rows=15,904
- `MQTT-Malformed_Data` (WiFI_and_MQTT): runs=2, splits=test,train, rows=6,877
- `Recon-VulScan` (WiFI_and_MQTT): runs=2, splits=test,train, rows=3,207
- `Recon-Ping_Sweep` (WiFI_and_MQTT): runs=2, splits=test,train, rows=926
- `TCP_IP-DDoS-UDP3` (WiFI_and_MQTT): runs=1, splits=train, rows=206,604
- `TCP_IP-DDoS-UDP4` (WiFI_and_MQTT): runs=1, splits=train, rows=206,343
- `TCP_IP-DDoS-UDP5` (WiFI_and_MQTT): runs=1, splits=train, rows=205,507
- `TCP_IP-DDoS-UDP8` (WiFI_and_MQTT): runs=1, splits=train, rows=204,105
- `TCP_IP-DDoS-TCP3` (WiFI_and_MQTT): runs=1, splits=train, rows=204,075

## Multi-Run vs Single-Run Types

- Types with multiple runs: **15**
- Types with single run: **42**