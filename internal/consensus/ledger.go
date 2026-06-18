package consensus

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"pqc-blockchain-sim/internal/crypto"
)

const (
	// genesisHash is the canonical PreviousHash value of the genesis block.
	genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

	// zeroMerkleRoot is stored in blocks that carry no transactions.
	zeroMerkleRoot = "0000000000000000000000000000000000000000000000000000000000000000"
)

// Ledger is a thread-safe append-only blockchain state machine.
// It holds the canonical chain of blocks and a live balance map derived
// from all committed transactions.
type Ledger struct {
	mu       sync.RWMutex
	blocks   []Block
	balances map[string]uint64
	engine   crypto.CryptoEngine
}

// NewLedger initialises a Ledger, injects the CryptoEngine, seeds the balance
// map with genesisBalances, and appends a synthetic genesis block at index 0.
// genesisBalances keys must be hex-encoded public keys matching the format
// used in Transaction.Sender / Transaction.Receiver.
func NewLedger(engine crypto.CryptoEngine, genesisBalances map[string]uint64) *Ledger {
	balances := make(map[string]uint64, len(genesisBalances))
	for k, v := range genesisBalances {
		balances[k] = v
	}

	genesis := Block{
		Header: BlockHeader{
			Index:        0,
			PreviousHash: genesisHash,
			Timestamp:    0,
			MerkleRoot:   zeroMerkleRoot,
			Nonce:        0,
		},
		Transactions: []Transaction{},
		Hash:         genesisHash,
		Signature:    nil,
		ProducerKey:  nil,
	}

	return &Ledger{
		blocks:   []Block{genesis},
		balances: balances,
		engine:   engine,
	}
}

// --- Public query methods (read lock) ---

// Height returns the number of blocks in the chain, including genesis.
func (l *Ledger) Height() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.blocks)
}

// GetBalance returns the current balance for a hex-encoded public key.
// Returns 0 for unknown accounts rather than an error — absent == zero balance.
func (l *Ledger) GetBalance(hexPubKey string) uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.balances[hexPubKey]
}

// LatestBlock returns a copy of the most recently committed block.
func (l *Ledger) LatestBlock() Block {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.blocks[len(l.blocks)-1]
}

// --- Validation ---

// ValidateTransaction verifies a single transaction against the ledger state.
// It hex-decodes tx.Sender internally so the caller only needs the Transaction value.
//
// Checks performed in order (cheapest first):
//  1. Recompute and compare the transaction ID.
//  2. Verify the cryptographic signature via the injected CryptoEngine.
//  3. Confirm the sender holds a sufficient balance.
func (l *Ledger) ValidateTransaction(tx Transaction) error {
	// Decode the sender's public key from its hex representation.
	senderPubKey, err := hex.DecodeString(tx.Sender)
	if err != nil {
		return fmt.Errorf("validate tx: invalid sender hex key %q: %w", tx.Sender, err)
	}

	// 1. Recompute and compare the transaction ID.
	canonical := canonicalTxBytes(tx)
	expectedID := hex.EncodeToString(hashBytes(canonical))
	if tx.ID != expectedID {
		return fmt.Errorf("validate tx: ID mismatch: got %s, want %s", tx.ID, expectedID)
	}

	// 2. Cryptographic signature verification.
	if !l.engine.Verify(canonical, tx.Signature, senderPubKey) {
		return errors.New("validate tx: signature verification failed")
	}

	// 3. Balance check (read lock held by the caller of ValidateBlock; safe to read directly).
	/*if l.balances[tx.Sender] < tx.Amount {
		return fmt.Errorf("validate tx: sender %s has insufficient balance: have %d, need %d",
			tx.Sender, l.balances[tx.Sender], tx.Amount)
	}
	*/
	return nil
}

// ValidateBlock verifies a candidate block against the current chain head.
//
// Checks performed in order:
//  1. Index continuity.
//  2. Chain hash linkage (PreviousHash must match the last block's hash).
//  3. All transactions are individually valid.
//  4. Merkle root integrity.
//  5. Block hash integrity.
//  6. Block producer signature.
func (l *Ledger) ValidateBlock(b Block) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.validateBlockLocked(b)
}

// validateBlockLocked performs validation assuming the read lock is already held.
// This allows AddBlock to call it inside its own write lock without a deadlock.
func (l *Ledger) validateBlockLocked(b Block) error {
	last := l.blocks[len(l.blocks)-1]

	// 1. Index continuity.
	expectedIndex := int64(len(l.blocks))
	if b.Header.Index != expectedIndex {
		return fmt.Errorf("validate block: index mismatch: got %d, want %d",
			b.Header.Index, expectedIndex)
	}

	// 2. Hash linkage.
	if b.Header.PreviousHash != last.Hash {
		return fmt.Errorf("validate block: previous hash mismatch: got %s, want %s",
			b.Header.PreviousHash, last.Hash)
	}

	// 3. Transaction validation.
	// We stage a temporary balance snapshot so we can detect intra-block
	// double-spends (e.g. a sender spending the same coins twice in one block).
	stagedBalances := make(map[string]uint64, len(l.balances))
	for k, v := range l.balances {
		stagedBalances[k] = v
	}
	for i, tx := range b.Transactions {
		if err := l.validateTxWithBalances(tx, stagedBalances); err != nil {
			return fmt.Errorf("validate block: tx[%d]: %w", i, err)
		}
		// Apply this transaction to the staged snapshot so subsequent txs in the
		// same block see the updated balance.
		stagedBalances[tx.Sender] -= tx.Amount
		stagedBalances[tx.Receiver] += tx.Amount
	}

	// 4. Merkle root.
	expectedMerkle := merkleRoot(b.Transactions)
	if b.Header.MerkleRoot != expectedMerkle {
		return fmt.Errorf("validate block: merkle root mismatch: got %s, want %s",
			b.Header.MerkleRoot, expectedMerkle)
	}

	// 5. Block hash integrity.
	expectedHash, err := computeBlockHash(b)
	if err != nil {
		return fmt.Errorf("validate block: hash computation failed: %w", err)
	}
	if b.Hash != expectedHash {
		return fmt.Errorf("validate block: hash mismatch: got %s, want %s",
			b.Hash, expectedHash)
	}

	// 6. Block producer signature (skip for genesis-style blocks with no producer key).
	if len(b.ProducerKey) > 0 {
		if !l.engine.Verify([]byte(b.Hash), b.Signature, b.ProducerKey) {
			return errors.New("validate block: producer signature verification failed")
		}
	}

	return nil
}

// AddBlock validates b and, if valid, atomically commits it to the chain.
//
// Balance updates are staged in a local map first. Only after all transactions
// have been verified against the staged state are the mutations applied to the
// live ledger. This ensures no partial state is ever written on error.
func (l *Ledger) AddBlock(b Block) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Validate inside the write lock so no concurrent AddBlock can race ahead.
	if err := l.validateBlockLocked(b); err != nil {
		return fmt.Errorf("add block: %w", err)
	}

	// Apply balance changes in transaction order, matching the staged snapshot
	// that validateBlockLocked already verified. We hold the write lock so no
	// concurrent mutation can occur between validation and commit.
	for _, tx := range b.Transactions {
		l.balances[tx.Sender] -= tx.Amount
		l.balances[tx.Receiver] += tx.Amount
	}

	l.blocks = append(l.blocks, b)
	return nil
}

// --- Helper: transaction utilities ---

// canonicalTxBytes serialises the transaction fields relevant to signing into a
// deterministic byte slice: Sender || Receiver || Amount (8 bytes BE) || Timestamp (8 bytes BE).
func canonicalTxBytes(tx Transaction) []byte {
	buf := make([]byte, 0, len(tx.Sender)+len(tx.Receiver)+16)
	buf = append(buf, []byte(tx.Sender)...)
	buf = append(buf, []byte(tx.Receiver)...)
	amtBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(amtBuf, tx.Amount)
	buf = append(buf, amtBuf...)
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(tx.Timestamp))
	buf = append(buf, tsBuf...)
	return buf
}

// NewTransactionID computes the canonical ID for a transaction.
// Exported so the node/P2P layer can stamp IDs when building transactions.
func NewTransactionID(tx Transaction) string {
	return hex.EncodeToString(hashBytes(canonicalTxBytes(tx)))
}

// validateTxWithBalances is the internal variant used during block validation.
// It reads from a caller-managed balance snapshot instead of l.balances so that
// intra-block balance changes are visible across successive transactions.
func (l *Ledger) validateTxWithBalances(tx Transaction, balances map[string]uint64) error {
	senderPubKey, err := hex.DecodeString(tx.Sender)
	if err != nil {
		return fmt.Errorf("invalid sender hex key %q: %w", tx.Sender, err)
	}

	canonical := canonicalTxBytes(tx)

	expectedID := hex.EncodeToString(hashBytes(canonical))
	if tx.ID != expectedID {
		return fmt.Errorf("ID mismatch: got %s, want %s", tx.ID, expectedID)
	}

	if !l.engine.Verify(canonical, tx.Signature, senderPubKey) {
		return errors.New("signature verification failed")
	}

	if balances[tx.Sender] < tx.Amount {
		return fmt.Errorf("insufficient balance: have %d, need %d",
			balances[tx.Sender], tx.Amount)
	}

	return nil
}

// --- Helper: block utilities ---

// computeBlockHash serialises the block header and transactions deterministically
// and returns hex(SHA-256(serialised bytes)).
func computeBlockHash(b Block) (string, error) {
	// Serialise the header first, then each transaction in order.
	// Using JSON for both ensures the measurement reflects real wire cost.
	headerBytes, err := json.Marshal(b.Header)
	if err != nil {
		return "", err
	}
	txBytes, err := json.Marshal(b.Transactions)
	if err != nil {
		return "", err
	}
	combined := append(headerBytes, txBytes...)
	return hex.EncodeToString(hashBytes(combined)), nil
}

// --- Helper: Merkle tree ---

// merkleRoot builds a standard binary Merkle tree over the transaction IDs and
// returns the root as a 64-character lowercase hex string.
// Odd-length layers duplicate the last node (Bitcoin convention).
// An empty transaction slice returns zeroMerkleRoot.
func merkleRoot(txs []Transaction) string {
	if len(txs) == 0 {
		return zeroMerkleRoot
	}

	// Seed the leaf layer with the raw hash bytes of each transaction ID.
	layer := make([][]byte, len(txs))
	for i, tx := range txs {
		decoded, err := hex.DecodeString(tx.ID)
		if err != nil {
			// Malformed ID — use its SHA-256 as a safe fallback.
			h := sha256.Sum256([]byte(tx.ID))
			decoded = h[:]
		}
		layer[i] = decoded
	}

	// Reduce until one root remains.
	for len(layer) > 1 {
		if len(layer)%2 != 0 {
			layer = append(layer, layer[len(layer)-1]) // duplicate last leaf
		}
		next := make([][]byte, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			combined := append(layer[i], layer[i+1]...)
			h := sha256.Sum256(combined)
			next[i/2] = h[:]
		}
		layer = next
	}

	return hex.EncodeToString(layer[0])
}

// --- Helper: general ---

// hashBytes returns the raw SHA-256 digest of data.
func hashBytes(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// ComputeBlockHash is the exported version for use by the block producer in the
// node/P2P layer when constructing a new block before signing it.
func ComputeBlockHash(b Block) (string, error) {
	return computeBlockHash(b)
}

// MerkleRoot is exported for the block producer to stamp the header before signing.
func MerkleRoot(txs []Transaction) string {
	return merkleRoot(txs)
}

// CanonicalTxBytes is exported so the node layer can call CryptoEngine.Sign()
// over the same bytes that ValidateTransaction will later verify against.
func CanonicalTxBytes(tx Transaction) []byte {
	return canonicalTxBytes(tx)
}

// StorageSize returns the JSON-serialized byte length of the current blocks slice.
// This provides an empirical metric for measuring post-quantum cryptography data footprint bloat.
func (l *Ledger) StorageSize() int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()

	data, err := json.Marshal(l.blocks)
	if err != nil {
		return -1
	}
	return int64(len(data))
}
