#!/bin/bash

# Function to clear existing tc rules, robustly
clear_tc_rules() {
  echo "Clearing existing tc rules on eth0..."
  tc qdisc del dev eth0 root > /dev/null 2>&1 || true
}

# Wait for eth0 to be available
wait_for_eth0() {
  local timeout=30
  local count=0
  while ! ip link show eth0 &> /dev/null; do
    if [ "$count" -ge "$timeout" ]; then
      echo "Error: eth0 not found after $timeout seconds. Exiting."
      exit 1
    fi
    echo "eth0 not found, waiting for network interface... (attempt $((count+1))/$timeout)"
    sleep 1
    count=$((count+1))
  done
  echo "eth0 interface is available."
}

wait_for_eth0
clear_tc_rules

case "$NODE_ID" in
  node1)
    echo "Applying netem rules for node1 (172.20.0.11)"
    # Traffic to node2 (172.20.0.12): 100ms latency
    tc qdisc add dev eth0 root handle 1: htb default 1
    tc class add dev eth0 parent 1: classid 1:1 htb rate 1000mbit
    tc qdisc add dev eth0 parent 1:1 netem delay 100ms
    tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip dst 172.20.0.12/32 flowid 1:1

    # Traffic to node3 (172.20.0.13): variable latency (50ms to 150ms)
    # Using `delay 100ms 50ms distribution normal` to simulate a mean delay of 100ms with a standard deviation of 50ms.
    # This will generally produce delays roughly between 50ms and 150ms for a normal distribution.
    tc class add dev eth0 parent 1: classid 1:2 htb rate 1000mbit
    tc qdisc add dev eth0 parent 1:2 netem delay 100ms 50ms distribution normal
    tc filter add dev eth0 protocol ip parent 1: prio 2 u32 match ip dst 172.20.0.13/32 flowid 1:2
    ;;
  node2)
    echo "Applying netem rules for node2 (172.20.0.12)"
    # Traffic to node1 (172.20.0.11): 100ms latency
    tc qdisc add dev eth0 root handle 1: htb default 1
    tc class add dev eth0 parent 1: classid 1:1 htb rate 1000mbit
    tc qdisc add dev eth0 parent 1:1 netem delay 100ms
    tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip dst 172.20.0.11/32 flowid 1:1

    # Traffic to node3 (172.20.0.13): 5% packet loss
    tc class add dev eth0 parent 1: classid 1:2 htb rate 1000mbit
    tc qdisc add dev eth0 parent 1:2 netem loss 5%
    tc filter add dev eth0 protocol ip parent 1: prio 2 u32 match ip dst 172.20.0.13/32 flowid 1:2
    ;;
  node3)
    echo "Applying netem rules for node3 (172.20.0.13)"
    # Traffic to node1 (172.20.0.11): variable latency (50ms to 150ms)
    tc qdisc add dev eth0 root handle 1: htb default 1
    tc class add dev eth0 parent 1: classid 1:1 htb rate 1000mbit
    tc qdisc add dev eth0 parent 1:1 netem delay 100ms 50ms distribution normal
    tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip dst 172.20.0.11/32 flowid 1:1

    # Traffic to node2 (172.20.0.12): 5% packet loss
    tc class add dev eth0 parent 1: classid 1:2 htb rate 1000mbit
    tc qdisc add dev eth0 parent 1:2 netem loss 5%
    tc filter add dev eth0 protocol ip parent 1: prio 2 u32 match ip dst 172.20.0.12/32 flowid 1:2
    ;;
  *)
    echo "NODE_ID environment variable is not set or recognized ($NODE_ID), no netem rules applied."
    ;;
esac

echo "Starting blockchain-node..."
exec /usr/local/bin/blockchain-node
