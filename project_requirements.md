Project Handbook & Aider Prompt
Blueprint
This document serves as the architectural specification and step-by-step prompt workbook
for building the Resource Usage Inspection in a Quantum-Resistant Blockchain Network.

1. Project Scope & Goals
The ultimate objective of this project is to measure, analyze, and document how transitioning
from classical elliptic curve cryptography to NIST-approved post-quantum cryptography (PQC)
affects resource consumption in a decentralized network.

The Problem
Classical cryptographic primitives such as ECDSA (Elliptic Curve Digital Signature Algorithm)
and X25519 (Diffie-Hellman key exchange) are vulnerable to Shor's algorithm running on a
sufficiently powerful quantum computer. While replacing them is mathematically
straightforward, PQC algorithms introduce substantial engineering trade-offs:
1.​ Public Key & Signature Expansion: PQC keys and signatures are orders of magnitude
larger than classical counterparts.
2.​ Computational Overhead: Algorithms have vastly different clock-cycle demands for
key generation, encapsulation, signing, and verification.

The Objective
Design and implement a single parameterizable blockchain node codebase in Go (go1.23+)
capable of running three distinct cryptographic models:
●​ Model 1 (Baseline / Traditional): TLS-like X25519 ephemeral key exchange + ECDSA
signatures.
●​ Model 2 (PQC Alpha): Crystals-Kyber-512 (KEM for handshakes) + Crystals-Dilithium2
(Signatures for blocks/transactions).
●​ Model 3 (PQC Beta): Crystals-Kyber-512 (KEM) + Falcon-512 (Signatures).

2. Experimental Methodology & Metrics
To capture clean, non-overlapping performance data, we will run three distinct test cycles
under simulated wide-area network (WAN) conditions.

Mathematical & Emulation Targets
We will emulate a WAN connecting our three nodes using Linux Traffic Control (tc) and Network
Emulation (netem):
●​ Latency (

):

uniform or Pareto distribution.

●​ Packet Loss (

):

random loss.

●​ Maximum Transmission Unit (MTU): Standard

.

Key Performance Indicators (KPIs)
The system will run automated transactions and collect the following data points:
1.​ Consensus Latency: Time taken for a block to be propagated, verified, and committed
by the majority of the network.
) and per block (
2.​ Bandwidth Footprint: Bytes transmitted per transaction (
capturing IP fragmentation characteristics.
3.​ CPU Utilization: Core cycles consumed by the node process during validation.
4.​ Storage Growth Rate (

),

): The byte-size growth of the ledger per 100 blocks.

3. System Architecture & Component Design
The blockchain node is modularly structured to keep the consensus loop identical while
swapping out the cryptographic engine:
┌─────────────────────────────────────────┐​
│
Main App
│​
│
(cmd/node)
│​
└────────────────────┬────────────────────┘​
│​
┌──────────────────────────────┼────────────────────────────
──┐​
▼
▼
▼​
┌──────────────┐
┌──────────────┐
┌──────────────┐​
│ Consensus │
│ Network │
│ Crypto │​
│ State & Tx │
│ (P2P Engine│
│ (Abstract │​
│ Validation │
│ & Handshake│
│ Interface) │​
└──────────────┘
└──────────────┘
└──────────────┘​

The Code Directory Map
pqc-blockchain-sim/​
├── cmd/​
│ └── node/​
│
└── main.go
├── internal/​
│ ├── crypto/​
│ │ ├── engine.go

# Reads env, boots engine, runs P2P and metrics loops​

# The abstract interface definition​

│ │ ├── traditional.go # Implementation using ECDSA/X25519​
│ │ └── pqc.go
# Implementation wrapping liboqs (Kyber, Dilithium, Falcon)​
│ ├── consensus/​
│ │ ├── ledger.go
# State database, Transaction and Block validations​
│ │ └── types.go
# Block and Transaction structs​
│ ├── network/​
│ │ └── p2p.go
# Handshake logic (KEM), connection manager, propagation​
│ └── metrics/​
│
└── collector.go
# CPU, RAM, bandwidth and validation time CSV logging​
└── scripts/​
└── emulate_network.sh # Automation script using tc/netem to apply WAN rules to veth
interfaces​

4. Phase-by-Phase Execution Plan
To build this systematically and maintain a pristine Git commit history for your lecturer, execute
the project in these phases:
PHASE 1: Core Protocol & PQC​
├─ 1.1 Implement Traditional Engine​
├─ 1.2 Implement PQC Engine (Kyber, Dilithium, Falcon)​
└─ 1.3 Implement Core Ledger Logic & Blocks​
PHASE 2: P2P Network, KEM Handshake & WAN Simulation​
├─ 2.1 Build TCP P2P Engine with KEM Key Exchange​
├─ 2.2 Construct the Network Emulation Scripts (tc netem)​
└─ 2.3 Verify Multi-Node Consensus Cycle​
PHASE 3: Metrics Engine & Local CSV Exporter​
├─ 3.1 Write internal/metrics collector​
└─ 3.2 Run stress tests and generate comparative resource analysis​
PHASE 4: Interactive Developer Interface (Dashboard UI)​
└─ 4.1 Build visual dashboard to monitor and interact with the ledger​

5. Sequential Aider Prompts
Use these exact, highly detailed prompt templates in your Aider terminal session. Work on them
one at a time, ensuring your code compiles and tests pass before moving to the next.

PROMPT 1: Implementing the Traditional Cryptographic Suite
Action: Copy and paste this prompt into Aider once you have run aider --model
gemini/gemini-2.5-pro in your terminal.
/add internal/crypto/engine.go​
/add internal/crypto/traditional.go​
​

Please implement the "TraditionalEngine" struct inside internal/crypto/traditional.go. ​
It must fully satisfy the CryptoEngine interface defined in internal/crypto/engine.go.​
​
Requirements:​
1. Use Go's standard library packages: 'crypto/ecdsa', 'crypto/elliptic', 'crypto/rand',
'crypto/sha256', and 'crypto/ecdh'.​
2. "Name()" must return "Traditional (X25519 + ECDSA)".​
3. "GenerateAsymmetricKeys()" must generate a standard P-256 (elliptic.P256()) ECDSA
private/public keypair.​
4. "Sign()" must sign the SHA-256 hash of the message using ECDSA.​
5. "Verify()" must verify the signature of the SHA-256 hashed message against the provided
ECDSA public key.​
6. "Encapsulate(peerPubKey)" must perform an ephemeral Diffie-Hellman key exchange:​
- Generate an ephemeral X25519 key (using 'crypto/ecdh').​
- Perform the key exchange against the peer's public X25519 key to derive the shared secret.​
- Return the ephemeral public key as the "ciphertext" and the derived shared secret.​
7. "Decapsulate(ciphertext, privKey)" must perform the corresponding Diffie-Hellman operation
using the local private X25519 key and the received ephemeral public key ("ciphertext") to
recover the shared secret.​
​
Ensure the code is robustly commented, includes comprehensive error handling, and runs
natively with standard Go commands.​

PROMPT 2: Implementing the PQC Suites wrapping liboqs
Action: Once Prompt 1 compiles, paste this to build the post-quantum engines.
/add internal/crypto/engine.go​
/add internal/crypto/pqc.go​
​
Please implement the "PQCEngine" struct inside internal/crypto/pqc.go.​
It must fully satisfy the CryptoEngine interface and wrap the liboqs-go library.​
​
Requirements:​
1. Define a struct `PQCEngine` that accepts configuration strings for both KEM and Signatures:​
type PQCEngine struct {​
name
string​
kemName
string​
sigName
string​
}​
2. Implement a factory function:​
- `NewKyberDilithiumEngine() *PQCEngine` (sets name to "PQC (Kyber512 + Dilithium2)",
kemName to "Kyber512", sigName to "Dilithium2")​
- `NewKyberFalconEngine() *PQCEngine` (sets name to "PQC (Kyber512 + Falcon512)",

kemName to "Kyber512", sigName to "Falcon512")​
3. "GenerateAsymmetricKeys()" must use `oqs.Signature` to generate a public/private key pair
for the configured signature scheme (Dilithium2 or Falcon512).​
4. "Sign()" must instantiate `oqs.Signature` for the active algorithm, sign the raw message
payload, and return the signature bytes.​
5. "Verify()" must check the signature of the message against the public key using the
corresponding `oqs.Signature` verifier.​
6. "Encapsulate(peerPubKey)" must instantiate `oqs.KeyEncapsulation` using the configured
KEM algorithm (Kyber512), generate the ciphertext and shared secret, and return them.​
7. "Decapsulate(ciphertext, privKey)" must use `oqs.KeyEncapsulation` to extract the shared
secret from the ciphertext using the local KEM private key.​
​
Ensure that `liboqs-go/oqs` structures are cleanly managed and freed to prevent memory
leaks, handling errors carefully.​

PROMPT 3: Designing the Blockchain Ledger & Blocks
Action: Once the cryptographic engines are complete, paste this to define your ledger data
structures.
/add internal/consensus/types.go​
/add internal/consensus/ledger.go​
​
Please write the transaction, block, and ledger data structures for our lightweight blockchain.​
​
Requirements:​
1. In `types.go`, define:​
- `Transaction` struct containing: ID (string), Sender (hex string), Receiver (hex string),
Amount (uint64), Signature ([]byte), and Timestamp (int64).​
- `BlockHeader` struct containing: Index (int64), PreviousHash (string), Timestamp (int64),
MerkleRoot (string), and Nonce (int64).​
- `Block` struct containing: Header (BlockHeader), Transactions ([]Transaction), and Hash
(string).​
2. In `ledger.go`, define the `Ledger` struct that acts as our state machine:​
- It must hold a list of validated Blocks (`[]Block`).​
- It must maintain an UTXO-like account balance map (`map[string]uint64`) to validate
balances.​
- It must accept a `CryptoEngine` at initialization to verify transactions and block signatures.​
3. Write a validation method for Transactions:​
- Recalculate transaction ID (SHA-256 hash of sender + receiver + amount + timestamp).​
- Verify the Transaction Signature using the injected `CryptoEngine.Verify()`.​
- Ensure the Sender has a sufficient balance in the account ledger.​
4. Write a validation method for Blocks:​
- Verify that the Block's `PreviousHash` matches the hash of the latest block.​

- Verify that all Transactions inside the block are individually valid.​
- Calculate the Merkle root of the transactions and confirm it matches the header.​
- Recalculate the block hash and confirm block integrity.​
​
Ensure the serialization of Blocks and Transactions into bytes is highly efficient (e.g., using
JSON or Gob encoding) as this will be measured under bandwidth metrics.​

PROMPT 4: Designing the P2P Networking Layer & KEM Handshake
Action: Paste this prompt to create the node-to-node communication protocol.
/add internal/network/p2p.go​
​
Please implement the peer-to-peer networking server for our blockchain nodes inside
internal/network/p2p.go.​
​
Requirements:​
1. Define a `PeerServer` struct that binds to a TCP port, accepts incoming connections, and
maintains an active peer pool.​
2. Implement a secure handshake protocol when establishing any peer connection:​
- When a connection is made, Node A sends its static KEM public key to Node B.​
- Node B uses the injected `CryptoEngine.Encapsulate()` against Node A's public key to
generate a shared secret and a ciphertext. Node B sends this ciphertext back to Node A.​
- Node B derives the shared secret. Node A receives the ciphertext and calls
`CryptoEngine.Decapsulate()` to recover the same shared secret.​
- Securely derive a session key from the shared secret. Log the handshake latency (duration
of this handshake) in microseconds.​
3. Implement a block and transaction propagation system:​
- When a node receives a new transaction, it validates it and floods it to all other peers.​
- When a block is successfully mined/produced, flood the block payload to all peers.​
- Use non-blocking goroutines and thread-safe channels to manage connection state.​
​
Ensure that the network engine handles disconnects cleanly and retries failed peer handshakes
dynamically.​

PROMPT 5: Setting Up the Metrics Collector (CSV Writer)
Action: Paste this to establish the resource usage performance instrumentation.
/add internal/metrics/collector.go​
​
Please implement a lightweight resource usage metrics collector inside
internal/metrics/collector.go.​
​
Requirements:​

1. Define a `MetricsCollector` struct that logs metrics at regular intervals and writes them to a
local CSV file.​
2. The CSV log must record:​
- Timestamp​
- CPU usage percentage (use Go's 'runtime' package or read directly from '/proc/stat' on
Linux)​
- Memory footprint in Megabytes (using 'runtime.MemStats')​
- Total bytes sent and received over the network interfaces​
- Handshake execution times (microseconds)​
- Block validation and verification times (milliseconds)​
- Cumulative block ledger storage size on disk​
3. Provide simple utility functions:​
- `StartCollection(interval time.Duration)`: Runs an asynchronous loop tracking system
statistics and writing rows to `metrics.csv`.​
- `LogHandshakeTime(duration time.Duration)`​
- `LogValidationTime(duration time.Duration)`​
​
Keep the resource utilization of the collector itself negligible so that it does not skew the
performance profile of the blockchain nodes.​
With this blueprint in your project directory, your local Gemini pair-programming workspace is
fully organized and ready to run.

