#!/usr/bin/env bash
# setup_netns.sh — victim + N attacker network namespaces on one L2 bridge.
#
# Genuine multi-source: each attacker is its own netns with a DISTINCT, deterministic
# MAC, so the victim-side capture can attribute every frame to its source DEVICE via
# the source MAC — even under IP spoofing (the generator spoofs IP, never Ethernet).
# All traffic stays on the local bridge → reliable spoofing, single-counted at veth-vic.
#
# Run with:  sudo ./setup_netns.sh [N]        (N attackers, default 3)
set -euo pipefail

N=${1:-3}
VICTIM_IP=172.28.5.3
PREFIX=24
BRIDGE=br-lab
VICTIM_MAC=02:00:00:00:00:fe

# Attacker i (1..N): IP 172.28.5.(104+i), MAC 02:00:00:00:00:0i, ns "attacker<i>".
attacker_ip()  { echo "172.28.5.$((104 + $1))"; }
attacker_mac() { printf '02:00:00:00:00:%02x' "$1"; }

# Idempotent cleanup (safe to re-run); clears up to 8 prior attacker namespaces.
ip netns del victim 2>/dev/null || true
for i in $(seq 1 8); do ip netns del "attacker$i" 2>/dev/null || true; done
ip link del "$BRIDGE" 2>/dev/null || true

# Shared L2 segment: a bridge in the root namespace (no IP, pure forwarding, STP off).
ip link add "$BRIDGE" type bridge
ip link set "$BRIDGE" up

# --- victim ---
ip netns add victim
ip link add veth-vic type veth peer name br-vic
ip link set br-vic master "$BRIDGE"
ip link set br-vic up
ip link set veth-vic netns victim
ip netns exec victim ip link set veth-vic address "$VICTIM_MAC"
ip netns exec victim ip addr add "${VICTIM_IP}/${PREFIX}" dev veth-vic
ip netns exec victim ip link set lo up
ip netns exec victim ip link set veth-vic up
# Don't let reverse-path filtering drop spoofed-source frames before capture.
ip netns exec victim sysctl -wq net.ipv4.conf.all.rp_filter=0
ip netns exec victim sysctl -wq net.ipv4.conf.default.rp_filter=0
ip netns exec victim sysctl -wq net.ipv4.conf.veth-vic.rp_filter=0

# --- attackers 1..N ---
for i in $(seq 1 "$N"); do
  ns="attacker$i"
  aip=$(attacker_ip "$i")
  amac=$(attacker_mac "$i")
  ip netns add "$ns"
  ip link add "veth-att$i" type veth peer name "br-att$i"
  ip link set "br-att$i" master "$BRIDGE"
  ip link set "br-att$i" up
  ip link set "veth-att$i" netns "$ns"
  ip netns exec "$ns" ip link set "veth-att$i" address "$amac"
  ip netns exec "$ns" ip addr add "${aip}/${PREFIX}" dev "veth-att$i"
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip link set "veth-att$i" up
done

echo "== bridge =="
ip -br link show "$BRIDGE"
echo "== victim ($VICTIM_MAC) =="
ip netns exec victim ip -br addr show veth-vic
for i in $(seq 1 "$N"); do
  echo "== attacker$i ($(attacker_mac "$i")) =="
  ip netns exec "attacker$i" ip -br addr show "veth-att$i"
done
echo "== connectivity (each attacker -> victim) =="
for i in $(seq 1 "$N"); do
  if ip netns exec "attacker$i" ping -c1 -W1 "$VICTIM_IP" >/dev/null 2>&1; then
    echo "  attacker$i -> $VICTIM_IP  OK"
  else
    echo "  attacker$i -> $VICTIM_IP  FAIL"
  fi
done
