#!/usr/bin/env python
"""Convert PCAP files to CICIoMT-style CSV files (45-column schema).

This script is designed for the CICIoMT2024 Bluetooth PCAP files so they can be
analyzed together with the WiFi/MQTT CSV data.

Key points:
- Produces the same column names and order as the WiFi/MQTT CSV files.
- Uses fixed-size packet windows (default 10 packets for Bluetooth).
- Supports reading PCAPs either from an extracted folder or directly from the
  `CICIoMT2024.tar` archive.
- Requires `tshark` (Wireshark CLI) to decode packets across link-layer types.

Note:
The original CICIoMT extraction pipeline is not publicly shipped with this repo.
This implementation reproduces the schema and uses deterministic, protocol-aware
window features that are suitable for unified EDA.
"""

from __future__ import annotations

import argparse
import io
import math
import struct
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
import tarfile

import numpy as np
import pandas as pd


OUTPUT_COLUMNS = [
    "Header_Length",
    "Protocol Type",
    "Duration",
    "Rate",
    "Srate",
    "Drate",
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
    "ece_flag_number",
    "cwr_flag_number",
    "ack_count",
    "syn_count",
    "fin_count",
    "rst_count",
    "HTTP",
    "HTTPS",
    "DNS",
    "Telnet",
    "SMTP",
    "SSH",
    "IRC",
    "TCP",
    "UDP",
    "DHCP",
    "ARP",
    "ICMP",
    "IGMP",
    "IPv",
    "LLC",
    "Tot sum",
    "Min",
    "Max",
    "AVG",
    "Std",
    "Tot size",
    "IAT",
    "Number",
    "Magnitue",
    "Radius",
    "Covariance",
    "Variance",
    "Weight",
]


TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.proto",
    "ip.ttl",
    "ip.hdr_len",
    "tcp.hdr_len",
    "tcp.flags.fin",
    "tcp.flags.syn",
    "tcp.flags.reset",
    "tcp.flags.push",
    "tcp.flags.ack",
    "tcp.flags.ecn",
    "tcp.flags.cwr",
]


def _check_tshark() -> None:
    if shutil.which("tshark") is None:
        print("[warn] tshark not found in PATH. Falling back to basic PCAP parser.")


def _run_tshark(pcap_path: Path) -> pd.DataFrame:
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
    ]
    for field in TSHARK_FIELDS:
        cmd.extend(["-e", field])

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        msg = proc.stderr.strip() or f"tshark failed for {pcap_path}"
        raise RuntimeError(msg)

    data = proc.stdout
    if not data.strip():
        return pd.DataFrame(columns=TSHARK_FIELDS)

    return pd.read_csv(
        io.StringIO(data),
        sep="\t",
        header=None,
        names=TSHARK_FIELDS,
        dtype=str,
        keep_default_na=False,
        na_filter=False,
        engine="python",
    )


def _run_basic_pcap_reader(pcap_path: Path) -> pd.DataFrame:
    rows = []
    with pcap_path.open("rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return pd.DataFrame(columns=TSHARK_FIELDS)
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            endian = "<"

        rh_fmt = endian + "IIII"
        rh_len = struct.calcsize(rh_fmt)
        while True:
            hdr = f.read(rh_len)
            if len(hdr) < rh_len:
                break
            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(rh_fmt, hdr)
            _pkt = f.read(incl_len)
            rows.append(
                {
                    "frame.time_epoch": f"{ts_sec + ts_usec / 1_000_000.0:.6f}",
                    "frame.len": str(incl_len),
                    "frame.protocols": "",
                    "ip.proto": "",
                    "ip.ttl": "",
                    "ip.hdr_len": "",
                    "tcp.hdr_len": "",
                    "tcp.flags.fin": "",
                    "tcp.flags.syn": "",
                    "tcp.flags.reset": "",
                    "tcp.flags.push": "",
                    "tcp.flags.ack": "",
                    "tcp.flags.ecn": "",
                    "tcp.flags.cwr": "",
                }
            )
    return pd.DataFrame(rows, columns=TSHARK_FIELDS)


def _to_num(series: pd.Series) -> np.ndarray:
    return pd.to_numeric(series, errors="coerce").fillna(0.0).to_numpy(dtype=float)


def _protocol_sets(protocol_col: pd.Series) -> list[set[str]]:
    out: list[set[str]] = []
    for value in protocol_col.astype(str).tolist():
        if not value:
            out.append(set())
            continue
        out.append(set(value.lower().split(":")))
    return out


def _estimate_header_lengths(
    frame_len: np.ndarray, ip_hdr_len: np.ndarray, tcp_hdr_len: np.ndarray, prot_sets: list[set[str]]
) -> np.ndarray:
    header_lengths = np.zeros_like(frame_len, dtype=float)
    for i, prot in enumerate(prot_sets):
        ip_h = ip_hdr_len[i]
        tcp_h = tcp_hdr_len[i]
        if tcp_h > 0 and ip_h > 0:
            header_lengths[i] = ip_h + tcp_h
        elif ip_h > 0:
            # UDP or non-TCP IPv4: assume at least 8-byte L4 header when UDP.
            header_lengths[i] = ip_h + (8.0 if "udp" in prot else 0.0)
        elif "arp" in prot:
            header_lengths[i] = 28.0
        else:
            # Bluetooth and other non-IP frames: fallback to captured frame size.
            header_lengths[i] = frame_len[i]
    return header_lengths


def _protocol_type(ip_proto: np.ndarray, prot_sets: list[set[str]]) -> np.ndarray:
    out = np.zeros_like(ip_proto, dtype=float)
    for i, proto_num in enumerate(ip_proto):
        if proto_num > 0:
            out[i] = proto_num
            continue
        prot = prot_sets[i]
        if "tcp" in prot:
            out[i] = 6.0
        elif "udp" in prot:
            out[i] = 17.0
        elif "icmp" in prot:
            out[i] = 1.0
        elif "igmp" in prot:
            out[i] = 2.0
        else:
            out[i] = 0.0
    return out


def _ratio(prot_sets: list[set[str]], token: str) -> float:
    if not prot_sets:
        return 0.0
    return float(sum(1 for p in prot_sets if token in p) / len(prot_sets))


def _covariance(x: np.ndarray, y: np.ndarray) -> float:
    if len(x) < 2:
        return 0.0
    return float(np.cov(x, y, ddof=0)[0, 1])


def _window_features(df: pd.DataFrame, window_size: int, drop_last: bool) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=OUTPUT_COLUMNS)

    ts = _to_num(df["frame.time_epoch"])
    frame_len = _to_num(df["frame.len"])
    ip_proto = _to_num(df["ip.proto"])
    ip_ttl = _to_num(df["ip.ttl"])
    ip_hdr_len = _to_num(df["ip.hdr_len"])
    tcp_hdr_len = _to_num(df["tcp.hdr_len"])

    fin = _to_num(df["tcp.flags.fin"])
    syn = _to_num(df["tcp.flags.syn"])
    rst = _to_num(df["tcp.flags.reset"])
    psh = _to_num(df["tcp.flags.push"])
    ack = _to_num(df["tcp.flags.ack"])
    ece = _to_num(df["tcp.flags.ecn"])
    cwr = _to_num(df["tcp.flags.cwr"])

    prot_sets = _protocol_sets(df["frame.protocols"])
    header_len = _estimate_header_lengths(frame_len, ip_hdr_len, tcp_hdr_len, prot_sets)
    proto_type = _protocol_type(ip_proto, prot_sets)

    rows = []
    n = len(df)
    step = window_size
    end_limit = n if not drop_last else n - (n % window_size)

    for start in range(0, end_limit, step):
        end = min(start + window_size, n)
        if end <= start:
            continue
        idx = slice(start, end)
        m = end - start

        w_ts = ts[idx]
        w_len = frame_len[idx]
        w_ttl = ip_ttl[idx]
        w_header = header_len[idx]
        w_proto = proto_type[idx]

        w_fin = fin[idx]
        w_syn = syn[idx]
        w_rst = rst[idx]
        w_psh = psh[idx]
        w_ack = ack[idx]
        w_ece = ece[idx]
        w_cwr = cwr[idx]
        w_prot_sets = prot_sets[start:end]

        duration_sec = float(max(w_ts[-1] - w_ts[0], 1e-9))
        iat_us = np.diff(w_ts, prepend=w_ts[0]) * 1_000_000.0

        rate = float(m / duration_sec)
        srate = rate
        drate = 0.0

        var_len = float(np.var(w_len))
        avg_len = float(np.mean(w_len))

        rows.append(
            {
                "Header_Length": float(np.mean(w_header)),
                "Protocol Type": float(np.mean(w_proto)),
                "Duration": float(np.mean(w_ttl)),
                "Rate": rate,
                "Srate": srate,
                "Drate": drate,
                "fin_flag_number": float(np.mean(w_fin)),
                "syn_flag_number": float(np.mean(w_syn)),
                "rst_flag_number": float(np.mean(w_rst)),
                "psh_flag_number": float(np.mean(w_psh)),
                "ack_flag_number": float(np.mean(w_ack)),
                "ece_flag_number": float(np.mean(w_ece)),
                "cwr_flag_number": float(np.mean(w_cwr)),
                "ack_count": float(np.sum(w_ack)),
                "syn_count": float(np.sum(w_syn)),
                "fin_count": float(np.sum(w_fin)),
                "rst_count": float(np.sum(w_rst)),
                "HTTP": _ratio(w_prot_sets, "http"),
                "HTTPS": _ratio(w_prot_sets, "tls"),
                "DNS": _ratio(w_prot_sets, "dns"),
                "Telnet": _ratio(w_prot_sets, "telnet"),
                "SMTP": _ratio(w_prot_sets, "smtp"),
                "SSH": _ratio(w_prot_sets, "ssh"),
                "IRC": _ratio(w_prot_sets, "irc"),
                "TCP": _ratio(w_prot_sets, "tcp"),
                "UDP": _ratio(w_prot_sets, "udp"),
                "DHCP": _ratio(w_prot_sets, "dhcp"),
                "ARP": _ratio(w_prot_sets, "arp"),
                "ICMP": _ratio(w_prot_sets, "icmp"),
                "IGMP": _ratio(w_prot_sets, "igmp"),
                "IPv": float(np.mean((w_proto > 0).astype(float))),
                "LLC": _ratio(w_prot_sets, "llc"),
                "Tot sum": float(np.sum(w_len)),
                "Min": float(np.min(w_len)),
                "Max": float(np.max(w_len)),
                "AVG": avg_len,
                "Std": float(np.std(w_len)),
                "Tot size": avg_len,
                "IAT": float(np.mean(iat_us)),
                "Number": float(m),
                "Magnitue": float(math.sqrt(np.mean(np.square(w_len)))),
                "Radius": float(math.sqrt(max(var_len, 0.0))),
                "Covariance": _covariance(w_len, iat_us),
                "Variance": var_len,
                "Weight": float(m * avg_len),
            }
        )

    out = pd.DataFrame(rows, columns=OUTPUT_COLUMNS)
    return out


def _to_output_relative(input_relative: str) -> PurePosixPath:
    p = PurePosixPath(input_relative)
    parts = list(p.parts)
    parts_lower = [x.lower() for x in parts]

    for i, part in enumerate(parts_lower):
        if part == "pcap":
            if "profiling" in parts_lower:
                parts[i] = "CSV"
            else:
                parts[i] = "csv"
            break

    return PurePosixPath(*parts[:-1], parts[-1] + ".csv")


def _write_csv(df: pd.DataFrame, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)


def _iter_extracted_pcaps(input_root: Path) -> list[Path]:
    return sorted(input_root.rglob("*.pcap"))


def _convert_one_pcap(
    pcap_path: Path, output_path: Path, window_size: int, drop_last: bool, skip_existing: bool
) -> None:
    if skip_existing and output_path.exists():
        print(f"[skip] {output_path}")
        return
    if shutil.which("tshark") is not None:
        packets = _run_tshark(pcap_path)
    else:
        packets = _run_basic_pcap_reader(pcap_path)
    features = _window_features(packets, window_size=window_size, drop_last=drop_last)
    _write_csv(features, output_path)
    print(f"[ok]   {pcap_path} -> {output_path} ({len(features)} rows)")


def convert_from_extracted(
    input_root: Path,
    output_root: Path,
    window_size: int,
    drop_last: bool,
    skip_existing: bool,
    max_files: int | None,
) -> None:
    pcaps = _iter_extracted_pcaps(input_root)
    if max_files is not None:
        pcaps = pcaps[:max_files]

    if not pcaps:
        raise RuntimeError(f"No .pcap files found under {input_root}")

    for pcap in pcaps:
        rel = pcap.relative_to(input_root).as_posix()
        out_rel = _to_output_relative(rel)
        out_path = output_root / Path(out_rel.as_posix())
        _convert_one_pcap(pcap, out_path, window_size, drop_last, skip_existing)


def convert_from_tar(
    tar_path: Path,
    output_root: Path,
    member_prefix: str,
    window_size: int,
    drop_last: bool,
    skip_existing: bool,
    max_files: int | None,
) -> None:
    with tarfile.open(tar_path, "r") as tf:
        members = [
            m
            for m in tf.getmembers()
            if m.isfile()
            and m.name.startswith(member_prefix)
            and m.name.lower().endswith(".pcap")
        ]
        members.sort(key=lambda m: m.name)
        if max_files is not None:
            members = members[:max_files]
        if not members:
            raise RuntimeError(
                f"No .pcap members found in {tar_path} with prefix '{member_prefix}'"
            )

        for member in members:
            out_rel = _to_output_relative(member.name)
            out_path = output_root / Path(out_rel.as_posix())
            if skip_existing and out_path.exists():
                print(f"[skip] {out_path}")
                continue

            extracted = tf.extractfile(member)
            if extracted is None:
                print(f"[warn] Could not read {member.name}; skipping.")
                continue

            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                tmp_path = Path(tmp.name)
                shutil.copyfileobj(extracted, tmp)

            try:
                _convert_one_pcap(tmp_path, out_path, window_size, drop_last, skip_existing=False)
            finally:
                tmp_path.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert PCAP files to CICIoMT-compatible 45-column CSV files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--input-root",
        type=Path,
        help="Root folder with extracted PCAP files (e.g., eda/data/interim/CICIoMT2024).",
    )
    group.add_argument(
        "--tar-file",
        type=Path,
        help="Path to CICIoMT2024.tar (reads PCAPs directly from archive).",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        required=True,
        help="Root output folder for generated CSV files.",
    )
    parser.add_argument(
        "--member-prefix",
        type=str,
        default="Bluetooth/",
        help="Tar member prefix to convert when using --tar-file (default: Bluetooth/).",
    )
    parser.add_argument(
        "--window-size",
        type=int,
        default=10,
        help="Packets per feature window (default: 10; matches CICIoMT Bluetooth setting).",
    )
    parser.add_argument(
        "--drop-last",
        action="store_true",
        help="Drop the final partial window.",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip output files that already exist.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Limit number of PCAP files processed (debug/dry runs).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.window_size <= 0:
        raise ValueError("--window-size must be > 0")

    _check_tshark()
    args.output_root.mkdir(parents=True, exist_ok=True)

    if args.input_root is not None:
        convert_from_extracted(
            input_root=args.input_root,
            output_root=args.output_root,
            window_size=args.window_size,
            drop_last=args.drop_last,
            skip_existing=args.skip_existing,
            max_files=args.max_files,
        )
    else:
        convert_from_tar(
            tar_path=args.tar_file,
            output_root=args.output_root,
            member_prefix=args.member_prefix,
            window_size=args.window_size,
            drop_last=args.drop_last,
            skip_existing=args.skip_existing,
            max_files=args.max_files,
        )


if __name__ == "__main__":
    main()
