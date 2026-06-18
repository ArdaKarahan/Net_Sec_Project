package consensus

import (
	"encoding/hex"
	"testing"
	"time"

	"pqc-blockchain-sim/internal/crypto"
)

// ---------------------------------------------------------------------------
// Test harness helpers
// ---------------------------------------------------------------------------

// testEngine is the shared crypto engine for all consensus tests.
// TraditionalEngine has no CGO dependency, keeping tests fast.
func newTestEngine() crypto.CryptoEngine {
	return crypto.NewTraditionalEngine()
}

// identity holds a key pair for a test participant.
type identity struct {
	pubHex  string // hex-encoded compressed P-256 public key (used as account ID)
	pubRaw  []byte // raw bytes
	privRaw []byte // raw 32-byte scalar
}

// newIdentity generates a fresh signing key pair.
func newIdentity(t *testing.T, e crypto.CryptoEngine) identity {
	t.Helper()
	pub, priv, err := e.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("GenerateAsymmetricKeys: %v", err)
	}
	return identity{
		pubHex:  hex.EncodeToString(pub),
		pubRaw:  pub,
		privRaw: priv,
	}
}

// makeTx builds, signs, and stamps a Transaction between two identities.
func makeTx(t *testing.T, e crypto.CryptoEngine, sender, receiver identity, amount uint64) Transaction {
	t.Helper()
	tx := Transaction{
		Sender:    sender.pubHex,
		Receiver:  receiver.pubHex,
		Amount:    amount,
		Timestamp: time.Now().UnixNano(),
	}
	tx.ID = NewTransactionID(tx)

	sig, err := e.Sign(CanonicalTxBytes(tx), sender.privRaw)
	if err != nil {
		t.Fatalf("Sign tx: %v", err)
	}
	tx.Signature = sig
	return tx
}

// makeBlock assembles a valid, signed block that extends the given ledger.
// The producer signs the block hash with producerPriv.
func makeBlock(t *testing.T, e crypto.CryptoEngine, l *Ledger,
	txs []Transaction, producer identity) Block {
	t.Helper()

	last := l.LatestBlock()
	hdr := BlockHeader{
		Index:        int64(l.Height()),
		PreviousHash: last.Hash,
		Timestamp:    time.Now().UnixNano(),
		MerkleRoot:   MerkleRoot(txs),
		Nonce:        0,
	}

	b := Block{
		Header:       hdr,
		Transactions: txs,
		ProducerKey:  producer.pubRaw,
	}

	hash, err := ComputeBlockHash(b)
	if err != nil {
		t.Fatalf("ComputeBlockHash: %v", err)
	}
	b.Hash = hash

	sig, err := e.Sign([]byte(hash), producer.privRaw)
	if err != nil {
		t.Fatalf("Sign block: %v", err)
	}
	b.Signature = sig
	return b
}

// ---------------------------------------------------------------------------
// 1. Genesis block initialisation and baseline balance verification
// ---------------------------------------------------------------------------

func TestLedger_Genesis_InitialState(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)

	l := NewLedger(e, map[string]uint64{
		alice.pubHex: 1000,
		bob.pubHex:   500,
	})

	// Chain starts at height 1 (the genesis block counts).
	if h := l.Height(); h != 1 {
		t.Errorf("Height() = %d, want 1", h)
	}

	// Balances are seeded correctly.
	if got := l.GetBalance(alice.pubHex); got != 1000 {
		t.Errorf("alice balance = %d, want 1000", got)
	}
	if got := l.GetBalance(bob.pubHex); got != 500 {
		t.Errorf("bob balance = %d, want 500", got)
	}

	// Unknown account returns 0, not an error.
	unknown := newIdentity(t, e)
	if got := l.GetBalance(unknown.pubHex); got != 0 {
		t.Errorf("unknown balance = %d, want 0", got)
	}
}

func TestLedger_Genesis_BlockStructure(t *testing.T) {
	e := newTestEngine()
	l := NewLedger(e, nil)

	genesis := l.LatestBlock()

	if genesis.Header.Index != 0 {
		t.Errorf("genesis index = %d, want 0", genesis.Header.Index)
	}
	if genesis.Header.PreviousHash != genesisHash {
		t.Errorf("genesis PreviousHash = %s, want %s", genesis.Header.PreviousHash, genesisHash)
	}
	if genesis.Hash != genesisHash {
		t.Errorf("genesis Hash = %s, want %s", genesis.Hash, genesisHash)
	}
	if len(genesis.Transactions) != 0 {
		t.Errorf("genesis has %d transactions, want 0", len(genesis.Transactions))
	}
}

// ---------------------------------------------------------------------------
// 2. Successful transaction validation and block application loop
// ---------------------------------------------------------------------------

func TestLedger_ValidateBlock_AndAddBlock_Success(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)
	producer := newIdentity(t, e)

	l := NewLedger(e, map[string]uint64{
		alice.pubHex: 1000,
		bob.pubHex:   200,
	})

	tx := makeTx(t, e, alice, bob, 300)
	block := makeBlock(t, e, l, []Transaction{tx}, producer)

	// ValidateBlock must pass before AddBlock.
	if err := l.ValidateBlock(block); err != nil {
		t.Fatalf("ValidateBlock: %v", err)
	}

	if err := l.AddBlock(block); err != nil {
		t.Fatalf("AddBlock: %v", err)
	}

	// Chain grew by one.
	if h := l.Height(); h != 2 {
		t.Errorf("Height() = %d, want 2", h)
	}

	// Balances reflect the transfer.
	if got := l.GetBalance(alice.pubHex); got != 700 {
		t.Errorf("alice balance = %d, want 700", got)
	}
	if got := l.GetBalance(bob.pubHex); got != 500 {
		t.Errorf("bob balance = %d, want 500", got)
	}
}

func TestLedger_MultiBlock_ChainGrowth(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)
	producer := newIdentity(t, e)

	l := NewLedger(e, map[string]uint64{
		alice.pubHex: 1000,
	})

	// Add three successive blocks, each transferring 100 from alice to bob.
	for i := 0; i < 3; i++ {
		tx := makeTx(t, e, alice, bob, 100)
		block := makeBlock(t, e, l, []Transaction{tx}, producer)
		if err := l.AddBlock(block); err != nil {
			t.Fatalf("AddBlock round %d: %v", i+1, err)
		}
	}

	if h := l.Height(); h != 4 { // genesis + 3
		t.Errorf("Height() = %d, want 4", h)
	}
	if got := l.GetBalance(alice.pubHex); got != 700 {
		t.Errorf("alice balance = %d, want 700", got)
	}
	if got := l.GetBalance(bob.pubHex); got != 300 {
		t.Errorf("bob balance = %d, want 300", got)
	}
}

func TestLedger_ValidateTransaction_Standalone(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)

	l := NewLedger(e, map[string]uint64{alice.pubHex: 500})

	tx := makeTx(t, e, alice, bob, 200)
	if err := l.ValidateTransaction(tx); err != nil {
		t.Errorf("ValidateTransaction on valid tx: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 3. Intra-block double-spend protection
// ---------------------------------------------------------------------------

// TestLedger_IntraBlock_DoubleSpend verifies that a block containing two
// transactions whose combined debit exceeds the sender's balance is rejected,
// even though each individual transaction is within the balance.
func TestLedger_IntraBlock_DoubleSpend(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)
	carol := newIdentity(t, e)
	producer := newIdentity(t, e)

	// Alice has 500. Two txs of 300 each = 600 total — must be rejected.
	l := NewLedger(e, map[string]uint64{alice.pubHex: 500})

	tx1 := makeTx(t, e, alice, bob, 300)
	tx2 := makeTx(t, e, alice, carol, 300)

	// Each tx individually looks valid (300 <= 500), but together they exceed
	// the balance. The block builder stamps the Merkle root over both txs.
	block := makeBlock(t, e, l, []Transaction{tx1, tx2}, producer)

	err := l.ValidateBlock(block)
	if err == nil {
		t.Fatal("ValidateBlock accepted a double-spend block — expected rejection")
	}
}

// TestLedger_IntraBlock_SenderReceivesAndSpendsInSameBlock verifies that a
// receiver can legitimately spend coins they received earlier in the same block.
func TestLedger_IntraBlock_ReceivedFundsCanBeSpent(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)
	carol := newIdentity(t, e)
	producer := newIdentity(t, e)

	// Alice: 500, Bob: 0. Block: Alice sends 300 to Bob, then Bob sends 200 to Carol.
	// Bob's staged balance after tx1 = 300, so tx2 (200) is valid.
	l := NewLedger(e, map[string]uint64{alice.pubHex: 500})

	tx1 := makeTx(t, e, alice, bob, 300)

	// tx2 must use bob's state after tx1 is applied in the staged snapshot.
	tx2 := Transaction{
		Sender:    bob.pubHex,
		Receiver:  carol.pubHex,
		Amount:    200,
		Timestamp: time.Now().UnixNano() + 1, // ensure distinct ID from tx1
	}
	tx2.ID = NewTransactionID(tx2)
	sig, err := e.Sign(CanonicalTxBytes(tx2), bob.privRaw)
	if err != nil {
		t.Fatalf("Sign tx2: %v", err)
	}
	tx2.Signature = sig

	block := makeBlock(t, e, l, []Transaction{tx1, tx2}, producer)
	if err := l.AddBlock(block); err != nil {
		t.Errorf("AddBlock rejected a valid intra-block receive-then-spend: %v", err)
	}

	// Carol ends up with 200.
	if got := l.GetBalance(carol.pubHex); got != 200 {
		t.Errorf("carol balance = %d, want 200", got)
	}
}

// TestLedger_SingleTx_InsufficientBalance verifies straightforward overdraft rejection.
func TestLedger_SingleTx_InsufficientBalance(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)
	producer := newIdentity(t, e)

	l := NewLedger(e, map[string]uint64{alice.pubHex: 100})

	tx := makeTx(t, e, alice, bob, 999) // way over balance
	block := makeBlock(t, e, l, []Transaction{tx}, producer)

	if err := l.ValidateBlock(block); err == nil {
		t.Fatal("ValidateBlock accepted an overdraft transaction")
	}
}

// ---------------------------------------------------------------------------
// 4. Merkle root recomputation integrity
// ---------------------------------------------------------------------------

// TestLedger_MerkleRoot_TransactionOrderTampered verifies that swapping the
// order of transactions in a block invalidates the Merkle root check.
func TestLedger_MerkleRoot_TransactionOrderTampered(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)
	carol := newIdentity(t, e)
	producer := newIdentity(t, e)

	l := NewLedger(e, map[string]uint64{
		alice.pubHex: 1000,
		bob.pubHex:   1000,
	})

	tx1 := makeTx(t, e, alice, carol, 100)
	tx2 := makeTx(t, e, bob, carol, 200)

	// Build a valid block with [tx1, tx2] order.
	block := makeBlock(t, e, l, []Transaction{tx1, tx2}, producer)

	// Swap transaction order without recomputing the Merkle root or block hash.
	tampered := block
	tampered.Transactions = []Transaction{tx2, tx1}
	// Header.MerkleRoot and Hash still reflect the original [tx1, tx2] order.

	err := l.ValidateBlock(tampered)
	if err == nil {
		t.Fatal("ValidateBlock accepted a block with tampered transaction order")
	}
}

// TestLedger_MerkleRoot_TransactionSubstituted verifies that replacing a
// transaction in the list (while keeping the Merkle root intact) causes the
// block hash check to catch the manipulation.
func TestLedger_MerkleRoot_TransactionSubstituted(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)
	carol := newIdentity(t, e)
	producer := newIdentity(t, e)

	l := NewLedger(e, map[string]uint64{
		alice.pubHex: 1000,
		bob.pubHex:   1000,
	})

	tx1 := makeTx(t, e, alice, carol, 100)
	tx2 := makeTx(t, e, bob, carol, 200)

	// Valid block with tx1 only.
	block := makeBlock(t, e, l, []Transaction{tx1}, producer)

	// Substitute tx2 in place of tx1 without updating MerkleRoot or Hash.
	tampered := block
	tampered.Transactions = []Transaction{tx2}

	err := l.ValidateBlock(tampered)
	if err == nil {
		t.Fatal("ValidateBlock accepted a block with a substituted transaction")
	}
}

// TestLedger_MerkleRoot_Deterministic verifies that MerkleRoot is pure and
// returns the same value for the same input regardless of call order.
func TestLedger_MerkleRoot_Deterministic(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)

	tx1 := makeTx(t, e, alice, bob, 50)
	tx2 := makeTx(t, e, alice, bob, 75)

	r1 := MerkleRoot([]Transaction{tx1, tx2})
	r2 := MerkleRoot([]Transaction{tx1, tx2})
	if r1 != r2 {
		t.Errorf("MerkleRoot is not deterministic: %s != %s", r1, r2)
	}

	// Order matters: [tx1,tx2] must differ from [tx2,tx1].
	r3 := MerkleRoot([]Transaction{tx2, tx1})
	if r1 == r3 {
		t.Error("MerkleRoot([tx1,tx2]) == MerkleRoot([tx2,tx1]) — order is not respected")
	}
}

func TestLedger_MerkleRoot_EmptyBlock(t *testing.T) {
	root := MerkleRoot([]Transaction{})
	if root != zeroMerkleRoot {
		t.Errorf("empty MerkleRoot = %s, want %s", root, zeroMerkleRoot)
	}
}

// ---------------------------------------------------------------------------
// 5. Additional validation edge cases
// ---------------------------------------------------------------------------

// TestLedger_ValidateBlock_WrongIndex ensures a block with a skipped index is rejected.
func TestLedger_ValidateBlock_WrongIndex(t *testing.T) {
	e := newTestEngine()
	producer := newIdentity(t, e)
	l := NewLedger(e, nil)

	block := makeBlock(t, e, l, nil, producer)
	block.Header.Index = 99 // wrong
	// Recompute hash so the hash check doesn't fire first.
	hash, _ := ComputeBlockHash(block)
	block.Hash = hash
	sig, _ := e.Sign([]byte(hash), producer.privRaw)
	block.Signature = sig

	if err := l.ValidateBlock(block); err == nil {
		t.Fatal("ValidateBlock accepted a block with wrong index")
	}
}

// TestLedger_ValidateBlock_WrongPreviousHash ensures chain linkage is enforced.
func TestLedger_ValidateBlock_WrongPreviousHash(t *testing.T) {
	e := newTestEngine()
	producer := newIdentity(t, e)
	l := NewLedger(e, nil)

	block := makeBlock(t, e, l, nil, producer)
	block.Header.PreviousHash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	hash, _ := ComputeBlockHash(block)
	block.Hash = hash
	sig, _ := e.Sign([]byte(hash), producer.privRaw)
	block.Signature = sig

	if err := l.ValidateBlock(block); err == nil {
		t.Fatal("ValidateBlock accepted a block with wrong PreviousHash")
	}
}

// TestLedger_ValidateBlock_TamperedHash ensures direct hash manipulation is caught.
func TestLedger_ValidateBlock_TamperedHash(t *testing.T) {
	e := newTestEngine()
	producer := newIdentity(t, e)
	l := NewLedger(e, nil)

	block := makeBlock(t, e, l, nil, producer)
	block.Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	if err := l.ValidateBlock(block); err == nil {
		t.Fatal("ValidateBlock accepted a block with a tampered hash")
	}
}

// TestLedger_ValidateBlock_TamperedProducerSignature checks block-level sig verification.
func TestLedger_ValidateBlock_TamperedProducerSignature(t *testing.T) {
	e := newTestEngine()
	producer := newIdentity(t, e)
	l := NewLedger(e, nil)

	block := makeBlock(t, e, l, nil, producer)

	// Flip bytes in the signature.
	corrupted := make([]byte, len(block.Signature))
	copy(corrupted, block.Signature)
	corrupted[0] ^= 0xFF
	block.Signature = corrupted

	if err := l.ValidateBlock(block); err == nil {
		t.Fatal("ValidateBlock accepted a block with a corrupted producer signature")
	}
}

// TestLedger_ValidateTransaction_TamperedID checks ID recomputation catches field changes.
func TestLedger_ValidateTransaction_TamperedID(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)
	l := NewLedger(e, map[string]uint64{alice.pubHex: 500})

	tx := makeTx(t, e, alice, bob, 100)
	tx.Amount = 999 // tamper amount without re-signing or updating ID

	if err := l.ValidateTransaction(tx); err == nil {
		t.Fatal("ValidateTransaction accepted a transaction with a mismatched ID")
	}
}

// TestLedger_ValidateTransaction_TamperedSignature checks sig verification catches key changes.
func TestLedger_ValidateTransaction_TamperedSignature(t *testing.T) {
	e := newTestEngine()
	alice := newIdentity(t, e)
	bob := newIdentity(t, e)
	l := NewLedger(e, map[string]uint64{alice.pubHex: 500})

	tx := makeTx(t, e, alice, bob, 100)
	tx.Signature[0] ^= 0xFF // corrupt the signature

	if err := l.ValidateTransaction(tx); err == nil {
		t.Fatal("ValidateTransaction accepted a transaction with a corrupted signature")
	}
}
