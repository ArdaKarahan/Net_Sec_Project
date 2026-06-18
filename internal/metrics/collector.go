// Package metrics implements asynchronous system-metrics collection for the
// blockchain simulation. It writes one CSV row per collection tick and exposes
// a Prometheus-compatible scrape endpoint on a configurable HTTP address.
//
// System metrics (CPU, memory, network I/O) are read from Linux /proc files.
// If those files are absent the values default to 0 with a one-time warning,
// so the node loop never crashes when running outside a Linux environment.
package metrics

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"pqc-blockchain-sim/internal/consensus"
)

// ---------------------------------------------------------------------------
// CSV row schema
// ---------------------------------------------------------------------------

// metricRow is one line in metrics.csv.
type metricRow struct {
	Timestamp          string
	CryptoMode         string
	CPUPercent         float64
	MemoryMB           float64
	NetBytesSent       uint64
	NetBytesRecv       uint64
	HandshakeTimeUs    int64
	ValidationTimeMs   int64
	LedgerStorageBytes int64
}

var csvHeader = []string{
	"timestamp",
	"crypto_mode",
	"cpu_percent",
	"memory_mb",
	"net_bytes_sent",
	"net_bytes_recv",
	"handshake_time_us",
	"validation_time_ms",
	"ledger_storage_bytes",
}

// ---------------------------------------------------------------------------
// MetricsCollector
// ---------------------------------------------------------------------------

// MetricsCollector gathers system and application metrics on a fixed interval
// and writes them to a CSV file and a Prometheus endpoint.
type MetricsCollector struct {
	cryptoMode string
	csvPath    string
	ledger     *consensus.Ledger // optional; nil disables ledger size tracking

	// Hook-injected event values — written from external goroutines, read and
	// zeroed by the collection loop under mu.
	mu               sync.Mutex
	lastHandshakeUs  int64
	lastValidationMs int64
	bytesSentDelta   uint64
	bytesRecvDelta   uint64

	// CPU delta tracking — /proc/stat is cumulative, so we keep the previous sample.
	prevCPUIdle  uint64
	prevCPUTotal uint64

	// Network I/O baseline — /proc/net/dev is cumulative since boot.
	// We subtract the first reading from all subsequent ones.
	netBaselineSent uint64
	netBaselineRecv uint64
	netBaselineSet  bool

	// procWarned suppresses repeated /proc read-error log lines.
	procCPUWarned bool
	procNetWarned bool

	// Prometheus metrics — initialised once via promOnce.
	promOnce        sync.Once
	promCPU         prometheus.Gauge
	promMemMB       prometheus.Gauge
	promHandshakeUs prometheus.Gauge
	promValidMs     prometheus.Gauge
	promNetSent     prometheus.Gauge
	promNetRecv     prometheus.Gauge
	promLedgerBytes prometheus.Gauge

	quit chan struct{}
}

// NewMetricsCollector creates a MetricsCollector.
//   - cryptoMode: one of "traditional", "pqc_dilithium", "pqc_falcon" —
//     written to every CSV row and Prometheus label.
//   - csvPath: path to the output CSV file (created/appended as needed).
//   - ledger: optional pointer to the live Ledger for storage-size tracking.
//     Pass nil to disable.
func NewMetricsCollector(cryptoMode, csvPath string, ledger *consensus.Ledger) *MetricsCollector {
	// Guard fallback: If the path is empty, explicitly force it to a safe local path
	if csvPath == "" {
		csvPath = "metrics.csv"
	}

	c := &MetricsCollector{
		cryptoMode: cryptoMode,
		csvPath:    csvPath,
		ledger:     ledger,
		quit:       make(chan struct{}),
	}
	c.initPrometheus()
	return c
}

// ---------------------------------------------------------------------------
// Prometheus initialisation
// ---------------------------------------------------------------------------

// initPrometheus registers all Prometheus metrics exactly once, handling the
// AlreadyRegisteredError that occurs when tests or multiple collectors share
// the default registry.
func (c *MetricsCollector) initPrometheus() {
	c.promOnce.Do(func() {
		labels := prometheus.Labels{"crypto_mode": c.cryptoMode}

		c.promCPU = mustRegisterGauge(prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "blockchain_cpu_percent",
			Help:        "Current CPU utilisation percentage.",
			ConstLabels: labels,
		}))
		c.promMemMB = mustRegisterGauge(prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "blockchain_memory_mb",
			Help:        "Process memory footprint in megabytes.",
			ConstLabels: labels,
		}))
		c.promHandshakeUs = mustRegisterGauge(prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "blockchain_handshake_duration_us",
			Help:        "Most recent KEM handshake latency in microseconds.",
			ConstLabels: labels,
		}))
		c.promValidMs = mustRegisterGauge(prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "blockchain_validation_duration_ms",
			Help:        "Most recent block validation time in milliseconds.",
			ConstLabels: labels,
		}))
		c.promNetSent = mustRegisterGauge(prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "blockchain_net_bytes_sent_total",
			Help:        "Cumulative bytes transmitted since node start.",
			ConstLabels: labels,
		}))
		c.promNetRecv = mustRegisterGauge(prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "blockchain_net_bytes_recv_total",
			Help:        "Cumulative bytes received since node start.",
			ConstLabels: labels,
		}))
		c.promLedgerBytes = mustRegisterGauge(prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "blockchain_ledger_bytes",
			Help:        "Serialised ledger size in bytes.",
			ConstLabels: labels,
		}))
	})
}

// mustRegisterGauge registers g with the default Prometheus registry.
// If the metric is already registered (e.g. in tests) it returns the existing
// collector rather than panicking.
func mustRegisterGauge(g prometheus.Gauge) prometheus.Gauge {
	err := prometheus.Register(g)
	if err == nil {
		return g
	}
	if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
		// Return the previously registered collector, which must be a Gauge.
		if existing, ok := are.ExistingCollector.(prometheus.Gauge); ok {
			return existing
		}
	}
	// Any other registration error is a programming mistake — surface it loudly.
	panic(fmt.Sprintf("metrics: prometheus registration failed: %v", err))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// StartCollection begins the asynchronous metrics loop, ticking at interval.
// Returns immediately; the loop runs until Stop() is called.
func (c *MetricsCollector) StartCollection(interval time.Duration) {
	go c.loop(interval)
}

// Stop signals the collection loop to exit gracefully.
func (c *MetricsCollector) Stop() {
	close(c.quit)
}

// StartPrometheusEndpoint starts an HTTP server on addr (e.g. ":8080") serving
// the /metrics scrape endpoint. Non-blocking; errors are logged.
func (c *MetricsCollector) StartPrometheusEndpoint(addr string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		log.Printf("[metrics] Prometheus endpoint listening on %s/metrics", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[metrics] Prometheus HTTP server error: %v", err)
		}
	}()
	// Close the server when the collector is stopped.
	go func() {
		<-c.quit
		_ = srv.Close()
	}()
}

// LogHandshakeTime records the duration of a completed KEM handshake.
// Thread-safe; safe to call from the P2P goroutine pool.
func (c *MetricsCollector) LogHandshakeTime(d time.Duration) {
	c.mu.Lock()
	c.lastHandshakeUs = d.Microseconds()
	c.mu.Unlock()
	c.promHandshakeUs.Set(float64(d.Microseconds()))
}

// LogValidationTime records the duration of a block validation pass.
// Thread-safe; safe to call from the consensus goroutine.
func (c *MetricsCollector) LogValidationTime(d time.Duration) {
	c.mu.Lock()
	c.lastValidationMs = d.Milliseconds()
	c.mu.Unlock()
	c.promValidMs.Set(float64(d.Milliseconds()))
}

// LogBandwidth accumulates bytes sent and received since the last collection tick.
// Thread-safe; call once per packet from the P2P write/read paths.
func (c *MetricsCollector) LogBandwidth(sentBytes, recvBytes uint64) {
	c.mu.Lock()
	c.bytesSentDelta += sentBytes
	c.bytesRecvDelta += recvBytes
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Collection loop
// ---------------------------------------------------------------------------

func (c *MetricsCollector) loop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Ensure the CSV file exists and has a header row.
	if err := c.ensureCSVHeader(); err != nil {
		log.Printf("[metrics] cannot open CSV file %s: %v", c.csvPath, err)
	}

	for {
		select {
		case <-c.quit:
			return
		case <-ticker.C:
			row := c.collect()
			if err := c.writeCSVRow(row); err != nil {
				log.Printf("[metrics] CSV write error: %v", err)
			}
			c.updatePrometheus(row)
		}
	}
}

// collect gathers one complete MetricRow snapshot.
func (c *MetricsCollector) collect() metricRow {
	row := metricRow{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		CryptoMode: c.cryptoMode,
	}

	row.CPUPercent = c.readCPUPercent()
	row.MemoryMB = c.readMemoryMB()
	row.NetBytesSent, row.NetBytesRecv = c.readNetIO()

	// Snapshot and zero event-driven fields atomically.
	c.mu.Lock()
	row.HandshakeTimeUs = c.lastHandshakeUs
	row.ValidationTimeMs = c.lastValidationMs
	// Add application-level bandwidth deltas on top of /proc/net/dev readings.
	row.NetBytesSent += c.bytesSentDelta
	row.NetBytesRecv += c.bytesRecvDelta
	c.bytesSentDelta = 0
	c.bytesRecvDelta = 0
	// Do NOT zero handshake/validation times — they represent the last known
	// value (useful for Grafana even between events).
	c.mu.Unlock()

	row.LedgerStorageBytes = c.readLedgerSize()
	return row
}

// ---------------------------------------------------------------------------
// System metric readers
// ---------------------------------------------------------------------------

// readCPUPercent parses /proc/stat and returns CPU utilisation as a percentage
// (0.0–100.0) computed from the delta since the last call.
// Returns 0 on error, logging a warning once.
func (c *MetricsCollector) readCPUPercent() float64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		if !c.procCPUWarned {
			log.Printf("[metrics] /proc/stat unavailable (%v) — CPU metrics will read 0", err)
			c.procCPUWarned = true
		}
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// fields[0] = "cpu", [1]=user [2]=nice [3]=system [4]=idle [5]=iowait
		// [6]=irq [7]=softirq [8]=steal (and possibly more)
		if len(fields) < 5 {
			return 0
		}
		var vals [8]uint64
		for i := 0; i < 8 && i+1 < len(fields); i++ {
			vals[i], _ = strconv.ParseUint(fields[i+1], 10, 64)
		}
		idle := vals[3] + vals[4] // idle + iowait
		total := vals[0] + vals[1] + vals[2] + vals[3] + vals[4] +
			vals[5] + vals[6] + vals[7]

		if c.prevCPUTotal == 0 {
			// First sample — no delta yet; store and return 0.
			c.prevCPUIdle = idle
			c.prevCPUTotal = total
			return 0
		}

		deltaIdle := idle - c.prevCPUIdle
		deltaTotal := total - c.prevCPUTotal
		c.prevCPUIdle = idle
		c.prevCPUTotal = total

		if deltaTotal == 0 {
			return 0
		}
		return (1.0 - float64(deltaIdle)/float64(deltaTotal)) * 100.0
	}
	return 0
}

// readMemoryMB returns the current process memory footprint in megabytes using
// runtime.ReadMemStats. This is always available regardless of OS.
func (c *MetricsCollector) readMemoryMB() float64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.Sys) / (1024 * 1024)
}

// readNetIO parses /proc/net/dev and returns cumulative bytes sent and received
// across all non-loopback interfaces since the first call to this method.
// Returns (0, 0) on error, logging a warning once.
func (c *MetricsCollector) readNetIO() (sent, recv uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		if !c.procNetWarned {
			log.Printf("[metrics] /proc/net/dev unavailable (%v) — network metrics will read 0", err)
			c.procNetWarned = true
		}
		return 0, 0
	}
	defer f.Close()

	var totalRecv, totalSent uint64
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // skip the two header lines
		}
		line := strings.TrimSpace(scanner.Text())
		// Format: "eth0: rx_bytes rx_pkts ... tx_bytes ..."
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colonIdx])
		if iface == "lo" {
			continue // skip loopback
		}
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 9 {
			continue
		}
		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		totalRecv += rxBytes
		totalSent += txBytes
	}

	if !c.netBaselineSet {
		c.netBaselineSent = totalSent
		c.netBaselineRecv = totalRecv
		c.netBaselineSet = true
		return 0, 0
	}

	// Guard against counter wraps (unlikely in a short experiment).
	if totalSent >= c.netBaselineSent {
		sent = totalSent - c.netBaselineSent
	}
	if totalRecv >= c.netBaselineRecv {
		recv = totalRecv - c.netBaselineRecv
	}
	return sent, recv
}

// readLedgerSize returns the JSON-serialised byte length of the current ledger
// chain. Returns -1 if no ledger is attached.
func (c *MetricsCollector) readLedgerSize() int64 {
	if c.ledger == nil {
		return -1
	}
	return c.ledger.StorageSize()
}

// ---------------------------------------------------------------------------
// CSV helpers
// ---------------------------------------------------------------------------

// ensureCSVHeader opens (or creates) the CSV file and writes the header row
// if the file is new or empty.
func (c *MetricsCollector) ensureCSVHeader() error {
	f, err := os.OpenFile(c.csvPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		w := csv.NewWriter(f)
		if err := w.Write(csvHeader); err != nil {
			return err
		}
		w.Flush()
	}
	return nil
}

// writeCSVRow appends one data row to the CSV file.
func (c *MetricsCollector) writeCSVRow(row metricRow) error {
	f, err := os.OpenFile(c.csvPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	record := []string{
		row.Timestamp,
		row.CryptoMode,
		fmt.Sprintf("%.4f", row.CPUPercent),
		fmt.Sprintf("%.4f", row.MemoryMB),
		strconv.FormatUint(row.NetBytesSent, 10),
		strconv.FormatUint(row.NetBytesRecv, 10),
		strconv.FormatInt(row.HandshakeTimeUs, 10),
		strconv.FormatInt(row.ValidationTimeMs, 10),
		strconv.FormatInt(row.LedgerStorageBytes, 10),
	}
	if err := w.Write(record); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

// ---------------------------------------------------------------------------
// Prometheus update
// ---------------------------------------------------------------------------

func (c *MetricsCollector) updatePrometheus(row metricRow) {
	c.promCPU.Set(row.CPUPercent)
	c.promMemMB.Set(row.MemoryMB)
	c.promHandshakeUs.Set(float64(row.HandshakeTimeUs))
	c.promValidMs.Set(float64(row.ValidationTimeMs))
	c.promNetSent.Set(float64(row.NetBytesSent))
	c.promNetRecv.Set(float64(row.NetBytesRecv))
	if row.LedgerStorageBytes >= 0 {
		c.promLedgerBytes.Set(float64(row.LedgerStorageBytes))
	}
}

// ---------------------------------------------------------------------------
// StorageSize helper exposed for testing
// ---------------------------------------------------------------------------

// LedgerJSONSize marshals v to JSON and returns the byte count.
// Exported for use in tests that want to verify the size calculation directly.
func LedgerJSONSize(v interface{}) int64 {
    data, err := json.Marshal(v)
    if err != nil {
        return -1
    }
    return int64(len(data))
}
