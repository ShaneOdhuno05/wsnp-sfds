#!/usr/bin/env python3
"""Orchestrate mixed-traffic capture. Per scenario: start a victim-ns capture (logged to
experiments/<name>.caplog), give the sniffer a lead-in, fire concurrent traffic_generator.py
streams (per scenarios.json), collect the pcap/csv. Manages the victim tcp_server.

Prereq:  sudo ./setup_netns.sh
Run:     sudo python3 scenario_runner.py <scenario|all> [options]
"""

import argparse, json, os, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(HERE, "attacker", "traffic_generator.py")
SERVER = os.path.join(HERE, "victim", "tcp_server.py")
CAPTURE = os.path.join(HERE, "victim", "packet_capture.py")
EXPDIR = os.path.join(HERE, "experiments")


def in_ns(ns, *pyargs):
    """`ip netns exec <ns> <python> -u <args...>`  (-u = unbuffered, so logs flush live)."""
    return ["ip", "netns", "exec", ns, sys.executable, "-u", *pyargs]


def stream_cmd(s, target_ip, attacker_ns):
    cmd = in_ns(
        attacker_ns,
        GEN,
        "--target-ip",
        target_ip,
        "--pps",
        str(s["pps"]),
        "--duration",
        str(s["duration"]),
        "--complete-handshake-ratio",
        str(s.get("complete_handshake_ratio", 1.0)),
        "--abortive-close",
    )
    if s.get("spoof"):
        cmd.append("--spoof-ips")
    if s.get("sequential_ports"):
        cmd.append("--sequential-ports")
    return cmd


def fire_stream(idx, s, target_ip, attacker_prefix):
    if s.get("start", 0):
        time.sleep(s["start"])
    ns = f"{attacker_prefix}{s.get('source', 1)}"  # genuine multi-source: stream -> its device's netns
    print(
        f"[runner]   +{s.get('start', 0):>4}s stream {idx} ({ns}): pps={s['pps']} "
        f"hs={s.get('complete_handshake_ratio', 1.0)} spoof={bool(s.get('spoof'))} dur={s['duration']}s"
    )
    subprocess.run(
        stream_cmd(s, target_ip, ns),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_scenario(
    sc, name, target_ip, attacker_prefix, victim_ns, iface, margin, lead_in
):
    cap_dur = sc["duration"] + margin
    log_path = os.path.join(EXPDIR, f"{name}.caplog")
    print(
        f"[runner] === {name} ===  {len(sc['streams'])} stream(s), "
        f"expected={sc.get('expected', [])}, capture {cap_dur}s"
    )
    caplog = open(log_path, "w")
    cap = subprocess.Popen(
        in_ns(
            victim_ns,
            CAPTURE,
            "--interface",
            iface,
            "--filter",
            "tcp port 8080",
            "--experiment-name",
            name,
            "--duration",
            str(cap_dur),
        ),
        stdout=caplog,
        stderr=subprocess.STDOUT,
    )
    time.sleep(lead_in)  # let the sniffer initialize
    if cap.poll() is not None:  # capture died during init -> show why
        caplog.flush()
        print(f"[runner]   ERROR: capture exited early (rc={cap.returncode}). Log:")
        print("   | " + open(log_path).read().strip().replace("\n", "\n   | "))
        caplog.close()
        return
    threads = [
        threading.Thread(target=fire_stream, args=(i, s, target_ip, attacker_prefix))
        for i, s in enumerate(sc["streams"])
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("[runner]   streams done; waiting for capture to finish...")
    cap.wait()
    caplog.close()
    last = (open(log_path).read().strip().splitlines() or ["(empty)"])[-1]
    print(f"[runner]   capture said: {last.strip()}")
    print(f"[runner] === {name} complete ===")


def main():
    p = argparse.ArgumentParser(description="Mixed-traffic capture orchestrator")
    p.add_argument("scenario", help="scenario name in scenarios.json, or 'all'")
    p.add_argument("--scenarios", default=os.path.join(HERE, "scenarios.json"))
    p.add_argument("--target-ip", default="172.28.5.3")
    p.add_argument(
        "--attacker-prefix",
        default="attacker",
        help="netns name prefix; a stream's 'source': i runs in <prefix><i> (default: attacker)",
    )
    p.add_argument("--victim-ns", default="victim")
    p.add_argument("--interface", default="veth-vic")
    p.add_argument("--margin", type=float, default=8.0)
    p.add_argument(
        "--lead-in", type=float, default=5.0, help="seconds to let the sniffer start"
    )
    p.add_argument("--no-server", action="store_true")
    args = p.parse_args()

    os.makedirs(EXPDIR, exist_ok=True)
    with open(args.scenarios) as f:
        scenarios = json.load(f)
    names = list(scenarios) if args.scenario == "all" else [args.scenario]
    for n in names:
        if n not in scenarios:
            print(f"[runner] unknown scenario: {n}")
            sys.exit(1)

    server = None
    try:
        if not args.no_server:
            print("[runner] starting victim tcp_server...")
            server = subprocess.Popen(
                in_ns(args.victim_ns, SERVER, "--port", "8080"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1)
        for n in names:
            run_scenario(
                scenarios[n],
                n,
                args.target_ip,
                args.attacker_prefix,
                args.victim_ns,
                args.interface,
                args.margin,
                args.lead_in,
            )
            time.sleep(3)
    finally:
        if server is not None:
            print("[runner] stopping tcp_server.")
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    main()
