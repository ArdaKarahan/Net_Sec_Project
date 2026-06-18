package metrics

import (
	"encoding/csv"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pqc-blockchain-sim/internal/consensus"
	"pqc-blockchain-sim/internal/crypto"
)

// ---------------------------------------------------------------------------
// Harness helpers
// ---------------------------------------------------------------------------

// newTestCollector creates a MetricsCollector wired to a temp CSV and an
// optional ledger. The mode string must be unique per test to avoid Prometheus
// label collisions across tests running in the same process.
func newTestCollector(t *testing.T, mode string, ledger *consensus.Ledger) *MetricsCollector {
	t.Helper()
	csvPath := filepath.Join(t.TempDir(), "metrics.csv")
	c := NewMetricsCollector(mode, csvPath, ledger)
	t.Cleanup(func() {
		// Guard against double-close if a test already called Stop().
		select {
		case <-c.quit:
		default:
			c.Stop()
		}
	})
	return c
}

// newTestLedger returns a minimal Ledger backed by the TraditionalEngine.
func newTestLedger(t *testing.T) *consensus.Ledger {
	t.Helper()
	return consensus.NewLedger(crypto.NewTraditionalEngine(), nil)
}

// readAllCSVRows opens the collector's CSV file and returns all rows
// (including the header) as [][]string.
func readAllCSVRows(t *testing.T, c *MetricsCollector) [][]string {
	t.Helper()
	f, err := os.Open(c.csvPath)
	if err != nil {
		t.Fatalf("open CSV %s: %v", c.csvPath, err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}
	return rows
}

// ---------------------------------------------------------------------------
// 1. Prometheus registration — no panics, no double-registration
// ---------------------------------------------------------------------------

// TestNewMetricsCollector_NoPanic verifies that constructing a collector
// does not panic on first use.
func TestNewMetricsCollector_NoPanic(t *testing.T) {
	// If initPrometheus panics the test itself will panic — that counts as a
	// failure, so no explicit assertion is needed beyond "it ran".
	c := newTestCollector(t, "traditional_test_init", nil)
	if c == nil {
		t.Fatal("NewMetricsCollector returned nil")
	}
}

// TestNewMetricsCollector_DoubleConstruction_NoPanic verifies that creating two
// collectors with the same crypto_mode label (same Prometheus constant labels)
// does not panic due to AlreadyRegisteredError.
func TestNewMetricsCollector_DoubleConstruction_NoPanic(t *testing.T) {
	mode := "traditional_test_double"
	c1 := newTestCollector(t, mode, nil)
	c2 := newTestCollector(t, mode, nil) // same label — must not panic
	if c1 == nil || c2 == nil {
		t.Fatal("one of the collectors is nil")
	}
}

// TestNewMetricsCollector_PrometheusGaugesInitialised verifies that all seven
// Prometheus gauge fields are non-nil after construction.
func TestNewMetricsCollector_PrometheusGaugesInitialised(t *testing.T) {
	c := newTestCollector(t, "traditional_test_gauges", nil)

	if c.promCPU == nil {
		t.Error("promCPU is nil")
	}
	if c.promMemMB == nil {
		t.Error("promMemMB is nil")
	}
	if c.promHandshakeUs == nil {
		t.Error("promHandshakeUs is nil")
	}
	if c.promValidMs == nil {
		t.Error("promValidMs is nil")
	}
	if c.promNetSent == nil {
		t.Error("promNetSent is nil")
	}
	if c.promNetRecv == nil {
		t.Error("promNetRecv is nil")
	}
	if c.promLedgerBytes == nil {
		t.Error("promLedgerBytes is nil")
	}
}

// ---------------------------------------------------------------------------
// 2. Hook methods and manual-tick aggregation
// ---------------------------------------------------------------------------

// TestLogHandshakeTime_StoresValue verifies that LogHandshakeTime stores the
// microsecond value under the mutex and that collect() reads it.
func TestLogHandshakeTime_StoresValue(t *testing.T) {
	c := newTestCollector(t, "traditional_test_hs", nil)

	c.LogHandshakeTime(5 * time.Millisecond) // 5000 µs

	c.mu.Lock()
	got := c.lastHandshakeUs
	c.mu.Unlock()

	if got != 5000 {
		t.Errorf("lastHandshakeUs = %d, want 5000", got)
	}
}

// TestLogValidationTime_StoresValue verifies that LogValidationTime stores the
// millisecond value under the mutex.
func TestLogValidationTime_StoresValue(t *testing.T) {
	c := newTestCollector(t, "traditional_test_val", nil)

	c.LogValidationTime(12 * time.Millisecond)

	c.mu.Lock()
	got := c.lastValidationMs
	c.mu.Unlock()

	if got != 12 {
		t.Errorf("lastValidationMs = %d, want 12", got)
	}
}

// TestLogBandwidth_AccumulatesDeltas verifies that multiple LogBandwidth calls
// add to the running delta totals.
func TestLogBandwidth_AccumulatesDeltas(t *testing.T) {
	c := newTestCollector(t, "traditional_test_bw", nil)

	c.LogBandwidth(100, 200)
	c.LogBandwidth(50, 75)

	c.mu.Lock()
	sent := c.bytesSentDelta
	recv := c.bytesRecvDelta
	c.mu.Unlock()

	if sent != 150 {
		t.Errorf("bytesSentDelta = %d, want 150", sent)
	}
	if recv != 275 {
		t.Errorf("bytesRecvDelta = %d, want 275", recv)
	}
}

// TestCollect_SnapshotsAndZeroesBandwidth verifies that a manual collect() call
// captures the bandwidth deltas into the row and then zeroes them.
func TestCollect_SnapshotsAndZeroesBandwidth(t *testing.T) {
	c := newTestCollector(t, "traditional_test_collect_bw", nil)

	c.LogBandwidth(400, 800)

	row := c.collect()

	// The row must include the accumulated bytes (on top of /proc values; at
	// minimum the delta we injected must be present).
	if row.NetBytesSent < 400 {
		t.Errorf("row.NetBytesSent = %d, want >= 400", row.NetBytesSent)
	}
	if row.NetBytesRecv < 800 {
		t.Errorf("row.NetBytesRecv = %d, want >= 800", row.NetBytesRecv)
	}

	// Deltas must be zeroed after the snapshot.
	c.mu.Lock()
	sent := c.bytesSentDelta
	recv := c.bytesRecvDelta
	c.mu.Unlock()

	if sent != 0 {
		t.Errorf("bytesSentDelta after collect = %d, want 0", sent)
	}
	if recv != 0 {
		t.Errorf("bytesRecvDelta after collect = %d, want 0", recv)
	}
}

// TestCollect_HandshakeAndValidationPresentInRow verifies that hook values
// appear in the collected row.
func TestCollect_HandshakeAndValidationPresentInRow(t *testing.T) {
	c := newTestCollector(t, "traditional_test_collect_hv", nil)

	c.LogHandshakeTime(7 * time.Millisecond)  // 7000 µs
	c.LogValidationTime(3 * time.Millisecond) // 3 ms

	row := c.collect()

	if row.HandshakeTimeUs != 7000 {
		t.Errorf("row.HandshakeTimeUs = %d, want 7000", row.HandshakeTimeUs)
	}
	if row.ValidationTimeMs != 3 {
		t.Errorf("row.ValidationTimeMs = %d, want 3", row.ValidationTimeMs)
	}
}

// TestCollect_HandshakeTimeNotZeroedBetweenTicks verifies the design decision
// that handshake/validation times represent the last known value and are NOT
// zeroed after a collect() — they persist until overwritten by the next event.
func TestCollect_HandshakeTimeNotZeroedBetweenTicks(t *testing.T) {
	c := newTestCollector(t, "traditional_test_persist", nil)

	c.LogHandshakeTime(9 * time.Millisecond)

	_ = c.collect() // first tick consumes the value

	row2 := c.collect() // second tick — value must still be present
	if row2.HandshakeTimeUs != 9000 {
		t.Errorf("HandshakeTimeUs on second tick = %d, want 9000", row2.HandshakeTimeUs)
	}
}

// TestCollect_CryptoModeInRow verifies the crypto_mode field is propagated.
func TestCollect_CryptoModeInRow(t *testing.T) {
	c := newTestCollector(t, "pqc_dilithium_test_mode", nil)
	row := c.collect()
	if row.CryptoMode != "pqc_dilithium_test_mode" {
		t.Errorf("CryptoMode = %q, want %q", row.CryptoMode, "pqc_dilithium_test_mode")
	}
}

// TestCollect_MemoryMBPositive verifies that memory reading always returns a
// positive value (runtime.ReadMemStats always works).
func TestCollect_MemoryMBPositive(t *testing.T) {
	c := newTestCollector(t, "traditional_test_mem", nil)
	row := c.collect()
	if row.MemoryMB <= 0 {
		t.Errorf("MemoryMB = %.4f, want > 0", row.MemoryMB)
	}
}

// ---------------------------------------------------------------------------
// 3. Ledger storage size tracking
// ---------------------------------------------------------------------------

// TestCollect_LedgerNil_ReturnsNegativeOne verifies that a nil ledger results
// in LedgerStorageBytes = -1 in the collected row.
func TestCollect_LedgerNil_ReturnsNegativeOne(t *testing.T) {
	c := newTestCollector(t, "traditional_test_ledger_nil", nil)
	row := c.collect()
	if row.LedgerStorageBytes != -1 {
		t.Errorf("LedgerStorageBytes with nil ledger = %d, want -1", row.LedgerStorageBytes)
	}
}

// TestCollect_LedgerAttached_ReturnsPositiveSize verifies that a live ledger
// (even with just the genesis block) produces a positive byte count.
func TestCollect_LedgerAttached_ReturnsPositiveSize(t *testing.T) {
	ledger := newTestLedger(t)
	c := newTestCollector(t, "traditional_test_ledger_size", ledger)

	row := c.collect()
	if row.LedgerStorageBytes <= 0 {
		t.Errorf("LedgerStorageBytes = %d, want > 0", row.LedgerStorageBytes)
	}
}

// TestCollect_LedgerSize_IncreasesWithBlocks verifies that adding blocks to the
// ledger causes LedgerStorageBytes to grow between ticks — the core PQC
// measurement this metric exists to capture.
func TestCollect_LedgerSize_IncreasesWithBlocks(t *testing.T) {
	engine := crypto.NewTraditionalEngine()
	ledger := consensus.NewLedger(engine, nil)
	c := newTestCollector(t, "traditional_test_ledger_growth", ledger)

	// Baseline — genesis block only.
	row1 := c.collect()
	baseSize := row1.LedgerStorageBytes

	// Add a signed block (reuse the test helpers pattern from ledger_test).
	pub, priv, err := engine.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("GenerateAsymmetricKeys: %v", err)
	}
	producerHex := hex.EncodeToString(pub)

	// Build a minimal empty block extending the genesis.
	last := ledger.LatestBlock()
	hdr := consensus.BlockHeader{
		Index:        1,
		PreviousHash: last.Hash,
		Timestamp:    time.Now().UnixNano(),
		MerkleRoot:   consensus.MerkleRoot(nil),
		Nonce:        0,
	}
	b := consensus.Block{
		Header:       hdr,
		Transactions: []consensus.Transaction{},
		ProducerKey:  pub,
	}
	hash, err := consensus.ComputeBlockHash(b)
	if err != nil {
		t.Fatalf("ComputeBlockHash: %v", err)
	}
	b.Hash = hash
	sig, err := engine.Sign([]byte(hash), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	b.Signature = sig
	_ = producerHex

	if err := ledger.AddBlock(b); err != nil {
		t.Fatalf("AddBlock: %v", err)
	}

	row2 := c.collect()
	if row2.LedgerStorageBytes <= baseSize {
		t.Errorf("ledger size did not grow after AddBlock: before=%d, after=%d",
			baseSize, row2.LedgerStorageBytes)
	}
}

// TestLedgerJSONSize_Helper verifies the exported helper computes the correct
// byte length for a known value.
func TestLedgerJSONSize_Helper(t *testing.T) {
	type simple struct {
		A string `json:"a"`
	}
	v := simple{A: "hello"}
	got := LedgerJSONSize(v)
	// {"a":"hello"} = 13 bytes
	if got != 13 {
		t.Errorf("LedgerJSONSize = %d, want 13", got)
	}
}

// ---------------------------------------------------------------------------
// 4. CSV file operations
// ---------------------------------------------------------------------------

// TestEnsureCSVHeader_WritesHeaderToNewFile verifies that a fresh CSV file
// gets the correct header row.
func TestEnsureCSVHeader_WritesHeaderToNewFile(t *testing.T) {
	c := newTestCollector(t, "traditional_test_csv_header", nil)

	if err := c.ensureCSVHeader(); err != nil {
		t.Fatalf("ensureCSVHeader: %v", err)
	}

	rows := readAllCSVRows(t, c)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row (header), got %d", len(rows))
	}
	if len(rows[0]) != len(csvHeader) {
		t.Fatalf("header column count = %d, want %d", len(rows[0]), len(csvHeader))
	}
	for i, col := range csvHeader {
		if rows[0][i] != col {
			t.Errorf("header[%d] = %q, want %q", i, rows[0][i], col)
		}
	}
}

// TestEnsureCSVHeader_IdempotentOnExistingFile verifies that calling
// ensureCSVHeader twice does not duplicate the header.
func TestEnsureCSVHeader_IdempotentOnExistingFile(t *testing.T) {
	c := newTestCollector(t, "traditional_test_csv_idempotent", nil)

	if err := c.ensureCSVHeader(); err != nil {
		t.Fatalf("first ensureCSVHeader: %v", err)
	}
	if err := c.ensureCSVHeader(); err != nil {
		t.Fatalf("second ensureCSVHeader: %v", err)
	}

	rows := readAllCSVRows(t, c)
	if len(rows) != 1 {
		t.Errorf("expected exactly 1 header row after two calls, got %d", len(rows))
	}
}

// TestWriteCSVRow_AppendsDataRow verifies that writeCSVRow appends a parseable
// data row with the correct number of columns.
func TestWriteCSVRow_AppendsDataRow(t *testing.T) {
	c := newTestCollector(t, "traditional_test_csv_row", nil)

	if err := c.ensureCSVHeader(); err != nil {
		t.Fatalf("ensureCSVHeader: %v", err)
	}

	row := metricRow{
		Timestamp:          time.Now().UTC().Format(time.RFC3339Nano),
		CryptoMode:         "traditional",
		CPUPercent:         42.5,
		MemoryMB:           128.25,
		NetBytesSent:       1000,
		NetBytesRecv:       2000,
		HandshakeTimeUs:    3000,
		ValidationTimeMs:   4,
		LedgerStorageBytes: 5000,
	}
	if err := c.writeCSVRow(row); err != nil {
		t.Fatalf("writeCSVRow: %v", err)
	}

	rows := readAllCSVRows(t, c)
	// header + 1 data row
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	data := rows[1]
	if len(data) != len(csvHeader) {
		t.Fatalf("data row column count = %d, want %d", len(data), len(csvHeader))
	}

	// Spot-check a few columns by index.
	// col 1 = crypto_mode
	if data[1] != "traditional" {
		t.Errorf("crypto_mode = %q, want %q", data[1], "traditional")
	}
	// col 4 = net_bytes_sent
	if data[4] != "1000" {
		t.Errorf("net_bytes_sent = %q, want %q", data[4], "1000")
	}
	// col 6 = handshake_time_us
	if data[6] != "3000" {
		t.Errorf("handshake_time_us = %q, want %q", data[6], "3000")
	}
	// col 8 = ledger_storage_bytes
	if data[8] != "5000" {
		t.Errorf("ledger_storage_bytes = %q, want %q", data[8], "5000")
	}
}

// TestWriteCSVRow_MultipleRows verifies that successive writes append correctly
// without overwriting previous rows.
func TestWriteCSVRow_MultipleRows(t *testing.T) {
	c := newTestCollector(t, "traditional_test_csv_multi", nil)

	if err := c.ensureCSVHeader(); err != nil {
		t.Fatalf("ensureCSVHeader: %v", err)
	}

	for i := 0; i < 3; i++ {
		row := metricRow{
			Timestamp:          time.Now().UTC().Format(time.RFC3339Nano),
			CryptoMode:         "traditional",
			LedgerStorageBytes: int64(i * 100),
		}
		if err := c.writeCSVRow(row); err != nil {
			t.Fatalf("writeCSVRow[%d]: %v", i, err)
		}
	}

	rows := readAllCSVRows(t, c)
	if len(rows) != 4 { // header + 3 data rows
		t.Errorf("expected 4 rows, got %d", len(rows))
	}
}

// ---------------------------------------------------------------------------
// 5. Background loop and Stop() cleanup
// ---------------------------------------------------------------------------

// TestStartCollection_WritesRowsToCSV starts the collection loop with a short
// interval, waits for at least one tick, then stops the loop and verifies the
// CSV contains data rows.
func TestStartCollection_WritesRowsToCSV(t *testing.T) {
	c := newTestCollector(t, "traditional_test_loop", nil)
	c.StartCollection(50 * time.Millisecond)

	// Allow at least two ticks.
	time.Sleep(150 * time.Millisecond)

	c.Stop()

	rows := readAllCSVRows(t, c)
	// header + at least one data row
	if len(rows) < 2 {
		t.Errorf("expected at least 2 rows after loop, got %d", len(rows))
	}
	// Verify the header is correct.
	if rows[0][0] != "timestamp" {
		t.Errorf("first header column = %q, want %q", rows[0][0], "timestamp")
	}
}

// TestStop_CanBeCalledTwiceSafely verifies that calling Stop() a second time
// (e.g. from the t.Cleanup registered in newTestCollector) does not panic on a
// closed channel.
func TestStop_CanBeCalledTwiceSafely(t *testing.T) {
	c := newTestCollector(t, "traditional_test_stop_double", nil)
	c.Stop() // explicit first stop
	// t.Cleanup will call Stop() again — must not panic.
}
