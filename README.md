# Resource Usage Inspection in a Quantum Resistant Blockchain Network

This project simulates a blockchain network with three nodes (`node1`, `node2`, `node3`) and integrates network emulation using `netem` along with a monitoring stack (Prometheus and Grafana) to observe resource utilization under various network conditions.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Setup and Running the Simulation](#setup-and-running-the-simulation)
- [Network Emulation Configuration](#network-emulation-configuration)
- [Monitoring Dashboards](#monitoring-dashboards)
- [Verification](#verification)

## Prerequisites
- Docker (version 20.10.0 or higher)
- Docker Compose (version 3.8 or higher)
- `make` (optional, for convenience)

## Setup and Running the Simulation

1.  **Build the Docker images:**
    ```bash
    docker-compose build
    ```

2.  **Start the simulation stack:**
    ```bash
    docker-compose up -d
    ```
    This will bring up the three blockchain nodes, their respective `node_exporter` instances, Prometheus, and Grafana.

3.  **Stop the simulation:**
    ```bash
    docker-compose down -v
    ```
    The `-v` flag will also remove the named volumes for Prometheus and Grafana data, ensuring a clean slate.

## Network Emulation Configuration

Network emulation rules are applied via an `entrypoint.sh` script within each node's container using `netem`. The following conditions are configured:

-   **Node 1 (172.20.0.11) to Node 2 (172.20.0.12):** 100ms latency.
-   **Node 2 (172.20.0.12) to Node 3 (172.20.0.13):** 5% packet loss.
-   **Node 1 (172.20.0.11) to Node 3 (172.20.0.13):** Variable latency (50ms to 150ms), simulated with a mean of 100ms and a standard deviation of 50ms (normal distribution).
-   Symmetric rules are applied in the reverse direction (e.g., Node 2 to Node 1 also has 100ms latency, Node 3 to Node 2 has 5% packet loss, etc.).

## Monitoring Dashboards

-   **Prometheus:**
    Access the Prometheus UI at: [http://localhost:9090](http://localhost:9090)
    You can query and visualize the collected metrics here. Targets for `node_exporter` instances are configured in `prometheus/prometheus.yml`.

-   **Grafana:**
    Access the Grafana UI at: [http://localhost:3000](http://localhost:3000)
    Default credentials:
    -   Username: `admin`
    -   Password: `admin`
    After logging in, you can add Prometheus as a data source (http://sim_prometheus:9090 or 172.20.0.200:9090) and import dashboards (e.g., Node Exporter Full dashboard ID 1860).

## Verification

To verify the `netem` rules are applied correctly, you can exec into a running node container and use `tc qdisc show dev eth0` and `ping`.

1.  **Get container ID/name:**
    ```bash
    docker ps
    ```
    Look for `sim_node1`, `sim_node2`, or `sim_node3`.

2.  **Exec into a container (e.g., node1):**
    ```bash
    docker exec -it sim_node1 bash
    ```

3.  **Check `netem` rules inside the container:**
    ```bash
    tc qdisc show dev eth0
    ```
    You should see `netem` configurations.

4.  **Test network latency/loss (e.g., from node1 to node2):**
    ```bash
    ping -c 5 172.20.0.12 # Should show ~100ms RTT
    ping -c 5 172.20.0.13 # Should show variable latency around 100ms
    ```
    From `node2` to `node3`:
    ```bash
    docker exec -it sim_node2 bash
    ping -c 20 172.20.0.13 # Should show approximately 5% packet loss
    ```
