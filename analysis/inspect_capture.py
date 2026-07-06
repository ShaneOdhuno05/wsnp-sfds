#!/usr/bin/env python3
"""Predict whether rate/ratio/pattern would fire for a capture CSV, mirroring the
per-source SN P detector's semantics. The ground truth the detector must
reproduce.

  - RATE    = AGGREGATE velocity: peak total SYN per window >= rate-thresh.
  - PATTERN = AGGREGATE bogon count: peak spoofed SYN per window >= pattern-thresh.
  - RATIO   = PER-SOURCE proportion: max over (window, DEVICE) of S/(S+A), strict
              '> ratio-thresh' (matches the detector's load-bearing +1). Grouping is
              per-DEVICE (--device-col), NOT per-IP: under spoofing one device emits
              many singleton bogon IPs that each read 100% per-IP -- per-device keeps
              a device's bogons diluted by its own completions.

If the device column is absent (e.g. the legacy single-source captures), every packet
is treated as one device, so the per-source ratio degenerates to a single window-level aggregate.

Usage: python3 inspect_capture.py <capture.csv> [--dt 1.0] [--ratio-thresh 0.70]
       [--pattern-thresh 3] [--rate-thresh 40] [--device-col device]
"""

import argparse, csv, collections

SPOOF_PREFIXES = (
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
)  # RFC 5737, == packet_encoder._is_src_spoof


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--dt", type=float, default=1.0, help="window width in seconds")
    ap.add_argument("--ratio-thresh", type=float, default=0.70)
    ap.add_argument(
        "--pattern-thresh", type=int, default=3, help="spoofed SYN/window to fire"
    )
    ap.add_argument(
        "--rate-thresh",
        type=int,
        default=60,
        help="total SYN/window (across sources) to fire velocity; multi-source gap is "
        "~(40, 89), so 60 sits centered with margin",
    )
    ap.add_argument(
        "--device-col",
        default="device",
        help="column identifying the source DEVICE for per-source ratio "
        "(falls back to a single device if the column is absent)",
    )
    args = ap.parse_args()

    W = collections.defaultdict(
        lambda: [0, 0, 0, 0]
    )  # window -> [syn, ack, spoofed_syn, total]   (aggregate: rate/pattern)
    WD = collections.defaultdict(
        lambda: [0, 0]
    )  # (window, device) -> [syn, ack]  (per-source ratio)
    t0 = None
    have_dev = None
    with open(args.csv, newline="") as f:
        for r in csv.DictReader(f):
            if have_dev is None:
                have_dev = args.device_col in r
            flags = int(r["tcp_flags_raw"])
            t = float(r["timestamp"])
            if t0 is None:
                t0 = t
            w = int((t - t0) // args.dt)
            dev = r[args.device_col] if have_dev else "__all__"
            cell = W[w]
            cell[3] += 1
            wd = WD[(w, dev)]
            if flags == 2:  # pure SYN
                cell[0] += 1
                wd[0] += 1
                if r["source_ip"].startswith(SPOOF_PREFIXES):
                    cell[2] += 1
            elif flags == 16:  # pure ACK (handshake completion)
                cell[1] += 1
                wd[1] += 1

    if not W:
        print("no packets")
        return
    wins = [W[w] for w in sorted(W)]
    peak_syn = max(s for s, a, sp, t in wins)
    peak_pkts = max(t for s, a, sp, t in wins)
    peak_spoof = max(sp for s, a, sp, t in wins)
    tot = [sum(c[i] for c in wins) for i in range(3)]

    # per-source ratio: strict '>' over (window, device); also the aggregate-per-window
    # ratio for contrast (what an aggregate detector -- blind to the source split -- sees).
    src = [(S / (S + A), w, d) for (w, d), (S, A) in WD.items() if (S + A)]
    max_src_ratio, mw, md = max(src) if src else (0.0, None, None)
    n_src_hi = sum(
        1 for (w, d), (S, A) in WD.items() if S > args.ratio_thresh * (S + A)
    )
    max_agg_ratio = max((s / (s + a) if (s + a) else 0.0 for s, a, sp, t in wins))
    n_dev = len({d for _, d in WD})

    rate_fire = peak_syn >= args.rate_thresh
    ratio_fire = n_src_hi > 0
    pattern_fire = peak_spoof >= args.pattern_thresh

    devnote = (
        f"col={args.device_col}" if have_dev else "no device column -> single device"
    )
    print(
        f"windows={len(wins)} (dt={args.dt}s)  devices={n_dev} ({devnote})  "
        f"totals: SYN={tot[0]} ACK={tot[1]} spoofedSYN={tot[2]}"
    )
    print(
        f"  peak SYN/window         = {peak_syn:>4}    -> RATE    {'FIRE' if rate_fire else 'calm'} (thr {args.rate_thresh})"
    )
    print(
        f"  max per-source S/(S+A)  = {max_src_ratio:>4.2f}    -> RATIO   {'FIRE' if ratio_fire else 'calm'} "
        f"(thr >{args.ratio_thresh}; {n_src_hi} src-window>thr; peak at win {mw} dev {md})"
    )
    print(
        f"      aggregate per-window max = {max_agg_ratio:>4.2f}    (what a source-blind aggregate ratio would see)"
    )
    print(
        f"  peak spoofed/window     = {peak_spoof:>4}    -> PATTERN {'FIRE' if pattern_fire else 'calm'} (thr {args.pattern_thresh})"
    )
    print(f"  peak packets/window     = {peak_pkts:>4}    (hard_limit must be >= this)")
    print(
        f"  => predicted label (rate,ratio,pattern) = "
        f"({'T' if rate_fire else 'F'},{'T' if ratio_fire else 'F'},{'T' if pattern_fire else 'F'})"
    )


if __name__ == "__main__":
    main()
