// cmd/node/main.go — entrypoint for the blockchain simulation node.
// All configuration comes from environment variables matching docker-compose.yml.
package main

import (
"encoding/hex"
"encoding/json"
"fmt"
"log"
"math/rand"
"os"
"os/signal"
"strconv"
"strings"
"syscall"
"time"

"pqc-blockchain-sim/internal/consensus"
"pqc-blockchain-sim/internal/crypto"
"pqc-blockchain-sim/internal/metrics"
"pqc-blockchain-sim/internal/network"
)

func init() {
log.SetFlags(log.LstdFlags | log.Lmicroseconds)
fmt.Println("╔══════════════════════════════════════════════════════╗")
fmt.Println("║  PQC Blockchain Simulation Node                      ║")
fmt.Println("║  Resource Usage Inspection: Classical vs PQC Crypto  ║")
fmt.Println("╚══════════════════════════════════════════════════════╝")
}

type config struct {
nodeID, listenAddr, blockchainMode, metricsAddr, csvPath string
peers                                                    []string
txInterval, blockInterval, metricsInterval               time.Duration
genesisBalance                                           uint64
}

func parseConfig() config {
nodeID := mustEnv("NODE_ID")
mode := mustEnv("BLOCKCHAIN_MODE")
port := envOr("P2P_PORT", "8000")
peersRaw := envOr("PEERS", "")
var peers []string
for _, p := range strings.Split(peersRaw, ",") {
if p = strings.TrimSpace(p); p != "" {
peers = append(peers, p)
}
}
return config{
nodeID:          nodeID,
listenAddr:      "0.0.0.0:" + port,
peers:           peers,
blockchainMode:  mode,
metricsAddr:     envOr("METRICS_ADDR", ":8080"),
csvPath:         envOr("CSV_PATH", "metrics.csv"),
txInterval:      envDuration("TX_INTERVAL_MS", 2000),
blockInterval:   envDuration("BLOCK_INTERVAL_MS", 5000),
metricsInterval: envDuration("METRICS_INTERVAL_MS", 1000),
genesisBalance:  envUint64("GENESIS_BALANCE", 1_000_000),
}
}

func mustEnv(k string) string {
if v := os.Getenv(k); v != "" {
return v
}
log.Fatalf("required env var %s is not set", k)
return ""
}

func envOr(k, d string) string {
if v := os.Getenv(k); v != "" {
return v
}
return d
}

func envDuration(k string, ms int64) time.Duration {
v := os.Getenv(k)
if v == "" {
return time.Duration(ms) * time.Millisecond
}
n, err := strconv.ParseInt(v, 10, 64)
if err != nil {
log.Printf("[config] bad %s=%q, using %dms", k, v, ms)
return time.Duration(ms) * time.Millisecond
}
return time.Duration(n) * time.Millisecond
}

func envUint64(k string, d uint64) uint64 {
v := os.Getenv(k)
if v == "" {
return d
}
n, err := strconv.ParseUint(v, 10, 64)
if err != nil {
log.Printf("[config] bad %s=%q, using %d", k, v, d)
return d
}
return n
}

func main() {
cfg := parseConfig()
log.Printf("=== Node: %s | Mode: %s | Listen: %s | Peers: %v",
cfg.nodeID, cfg.blockchainMode, cfg.listenAddr, cfg.peers)

// Step 1 — CryptoEngine
var engine crypto.CryptoEngine
switch cfg.blockchainMode {
case "traditional":
engine = crypto.NewTraditionalEngine()
case "pqc_dilithium":
engine = crypto.NewKyberDilithiumEngine()
case "pqc_falcon":
engine = crypto.NewKyberFalconEngine()
default:
log.Fatalf("unknown BLOCKCHAIN_MODE %q", cfg.blockchainMode)
}
log.Printf("[init] engine: %s", engine.Name())

// Step 2 — Signing keys
sigPub, sigPriv, err := engine.GenerateAsymmetricKeys()
if err != nil {
log.Fatalf("[init] GenerateAsymmetricKeys: %v", err)
}
sigPubHex := hex.EncodeToString(sigPub)
log.Printf("[init] pubkey: %s...", sigPubHex[:16])

// Step 3 — Genesis (Option C: self-loop, balance never depletes)
genesisBalances := map[string]uint64{sigPubHex: cfg.genesisBalance}

// Step 4 — Ledger
ledger := consensus.NewLedger(engine, genesisBalances)
log.Printf("[init] ledger ready | height: %d | balance: %d",
ledger.Height(), ledger.GetBalance(sigPubHex))

// Step 5 — PeerServer (generates KEM keys internally)
server, err := network.NewPeerServer(cfg.listenAddr, engine, ledger)
if err != nil {
log.Fatalf("[init] NewPeerServer: %v", err)
}

// Step 6 — MetricsCollector
collector := metrics.NewMetricsCollector(cfg.blockchainMode, cfg.csvPath, ledger)

// Step 7 — Start background services
go func() {
if err := server.ListenAndServe(); err != nil {
log.Printf("[p2p] ListenAndServe: %v", err)
}
}()
collector.StartCollection(cfg.metricsInterval)
collector.StartPrometheusEndpoint(cfg.metricsAddr)
server.ConnectToPeers(cfg.peers)

// Step 8 — Settle window for peer handshakes
log.Printf("[init] waiting 2s for handshakes to settle...")
time.Sleep(2 * time.Second)

done := make(chan struct{})
pending := make(chan consensus.Transaction, 256)

// Transaction generator goroutine
go func() {
t := time.NewTicker(cfg.txInterval)
defer t.Stop()
for {
select {
case <-done:
return
case <-t.C:
tx := buildTx(sigPubHex, sigPriv, engine)
if tx == nil {
continue
}
if err := ledger.ValidateTransaction(*tx); err != nil {
log.Printf("[sim] tx invalid: %v", err)
continue
}
if raw, err := json.Marshal(tx); err == nil {
collector.LogBandwidth(uint64(len(raw)), 0)
}
if err := server.BroadcastTransaction(*tx); err != nil {
log.Printf("[sim] BroadcastTx: %v", err)
continue
}
select {
case pending <- *tx:
default:
}
}
}
}()

// Block producer goroutine
go func() {
t := time.NewTicker(cfg.blockInterval)
defer t.Stop()
for {
select {
case <-done:
return
case <-t.C:
var batch []consensus.Transaction
drain:
for len(batch) < 10 {
select {
case tx := <-pending:
batch = append(batch, tx)
default:
break drain
}
}
if len(batch) == 0 {
continue
}
block := buildBlock(batch, ledger, sigPub, sigPriv, engine)
if block == nil {
continue
}
start := time.Now()
if err := ledger.AddBlock(*block); err != nil {
log.Printf("[sim] AddBlock: %v", err)
continue
}
collector.LogValidationTime(time.Since(start))
if raw, err := json.Marshal(block); err == nil {
collector.LogBandwidth(uint64(len(raw)), 0)
log.Printf("[sim] block %d | txs:%d | height:%d | %dB",
block.Header.Index, len(batch), ledger.Height(), len(raw))
}
if err := server.BroadcastBlock(*block); err != nil {
log.Printf("[sim] BroadcastBlock: %v", err)
}
}
}
}()

// Inbound event consumer goroutine
go func() {
for {
select {
case <-done:
return
case tx := <-server.InboundTx:
select {
case pending <- tx:
default:
}
case block := <-server.InboundBlock:
log.Printf("[net] inbound block %d | height:%d",
block.Header.Index, ledger.Height())
if raw, err := json.Marshal(block); err == nil {
collector.LogBandwidth(0, uint64(len(raw)))
}
}
}
}()

log.Printf("[sim] node %s running — Ctrl+C to stop", cfg.nodeID)

sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
sig := <-sigCh
log.Printf("[main] %v received — shutting down...", sig)

close(done)
time.Sleep(500 * time.Millisecond)
collector.Stop()
server.Stop()
log.Printf("[main] done | node:%s height:%d csv:%s",
cfg.nodeID, ledger.Height(), cfg.csvPath)
}

func buildTx(pubHex string, privKey []byte, engine crypto.CryptoEngine) *consensus.Transaction {
tx := consensus.Transaction{
Sender:    pubHex,
Receiver:  pubHex,
Amount:    uint64(rand.Intn(100) + 1),
Timestamp: time.Now().UnixNano(),
}
tx.ID = consensus.NewTransactionID(tx)
sig, err := engine.Sign(consensus.CanonicalTxBytes(tx), privKey)
if err != nil {
log.Printf("[sim] Sign tx: %v", err)
return nil
}
tx.Signature = sig
return &tx
}

func buildBlock(
txs []consensus.Transaction,
ledger *consensus.Ledger,
producerPub, producerPriv []byte,
engine crypto.CryptoEngine,
) *consensus.Block {
last := ledger.LatestBlock()
hdr := consensus.BlockHeader{
Index:        int64(ledger.Height()),
PreviousHash: last.Hash,
Timestamp:    time.Now().UnixNano(),
MerkleRoot:   consensus.MerkleRoot(txs),
}
b := consensus.Block{Header: hdr, Transactions: txs, ProducerKey: producerPub}
hash, err := consensus.ComputeBlockHash(b)
if err != nil {
log.Printf("[sim] ComputeBlockHash: %v", err)
return nil
}
b.Hash = hash
sig, err := engine.Sign([]byte(hash), producerPriv)
if err != nil {
log.Printf("[sim] Sign block: %v", err)
return nil
}
b.Signature = sig
return &b
}
