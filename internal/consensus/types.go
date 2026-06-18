package consensus

// Transaction represents a signed transfer of value between two participants.
// The canonical byte representation for signing and ID derivation is:
//
//	Sender + Receiver + big-endian(Amount) + big-endian(Timestamp)
//
// This avoids JSON overhead on the hot signing path and keeps hashing deterministic.
type Transaction struct {
	// ID is hex(SHA-256(canonical tx bytes)). Recomputed on validation to detect tampering.
	ID string `json:"id"`

	// Sender is the hex-encoded compressed public key of the sending party.
	// It doubles as the account identifier in the ledger balance map.
	Sender string `json:"sender"`

	// Receiver is the hex-encoded compressed public key of the receiving party.
	Receiver string `json:"receiver"`

	// Amount is the transfer value in the smallest indivisible unit.
	Amount uint64 `json:"amount"`

	// Signature is the output of CryptoEngine.Sign() over the canonical tx bytes,
	// produced with the sender's private key.
	Signature []byte `json:"signature"`

	// Timestamp is Unix time in nanoseconds. Nanosecond resolution minimises
	// the chance of two transactions from the same sender sharing an identical ID.
	Timestamp int64 `json:"timestamp"`
}

// BlockHeader contains the metadata that chains this block to its predecessor
// and commits to the full transaction set via the Merkle root.
type BlockHeader struct {
	// Index is the zero-based block height. Genesis is 0.
	Index int64 `json:"index"`

	// PreviousHash is hex(SHA-256(canonical serialization of the previous Block)).
	// The genesis block stores 64 hex zeros here.
	PreviousHash string `json:"previous_hash"`

	// Timestamp is Unix time in nanoseconds when the block was produced.
	Timestamp int64 `json:"timestamp"`

	// MerkleRoot is the root of the binary Merkle tree built over all Transaction IDs
	// in this block. An empty block stores 64 hex zeros.
	MerkleRoot string `json:"merkle_root"`

	// Nonce is reserved for proof-of-work experiments. Set to 0 in the current
	// consensus model.
	Nonce int64 `json:"nonce"`
}

// Block is the unit of ledger extension. A valid block must be cryptographically
// chained to its predecessor and carry a producer signature over its own hash.
type Block struct {
	Header       BlockHeader   `json:"header"`
	Transactions []Transaction `json:"transactions"`

	// Hash is hex(SHA-256(canonical serialization of Header + Transactions)).
	// Recomputed during validation to assert integrity.
	Hash string `json:"hash"`

	// Signature is the output of CryptoEngine.Sign() over []byte(Hash),
	// produced by the block producer's private key.
	Signature []byte `json:"signature"`

	// ProducerKey is the compressed public key of the block producer.
	// Stored in the block so any node can call CryptoEngine.Verify() without
	// out-of-band key distribution.
	ProducerKey []byte `json:"producer_key"`
}
