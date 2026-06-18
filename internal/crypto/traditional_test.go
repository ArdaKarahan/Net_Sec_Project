package crypto

import (
	"bytes"
	"testing"
)

// TestTraditionalEngine_Name verifies the engine returns the correct identifier.
func TestTraditionalEngine_Name(t *testing.T) {
	e := NewTraditionalEngine()
	if got := e.Name(); got != "Traditional (X25519 + ECDSA)" {
		t.Errorf("Name() = %q, want %q", got, "Traditional (X25519 + ECDSA)")
	}
}

// TestTraditionalEngine_GenerateAsymmetricKeys checks that key generation
// produces non-empty, distinct keys of expected lengths.
func TestTraditionalEngine_GenerateAsymmetricKeys(t *testing.T) {
	e := NewTraditionalEngine()

	pub, priv, err := e.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("GenerateAsymmetricKeys() error: %v", err)
	}

	// Compressed P-256 public key: 1 prefix byte + 32 bytes = 33 bytes.
	if len(pub) != 33 {
		t.Errorf("public key length = %d, want 33", len(pub))
	}
	// Private scalar padded to 32 bytes.
	if len(priv) != 32 {
		t.Errorf("private key length = %d, want 32", len(priv))
	}

	// Two independent calls must produce different keys.
	pub2, priv2, err := e.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("second GenerateAsymmetricKeys() error: %v", err)
	}
	if bytes.Equal(pub, pub2) {
		t.Error("two generated public keys are identical — RNG broken?")
	}
	if bytes.Equal(priv, priv2) {
		t.Error("two generated private keys are identical — RNG broken?")
	}
}

// TestTraditionalEngine_SignVerify_RoundTrip is the core correctness test:
// a signature produced with a private key must verify against the matching
// public key.
func TestTraditionalEngine_SignVerify_RoundTrip(t *testing.T) {
	e := NewTraditionalEngine()
	pub, priv, err := e.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("GenerateAsymmetricKeys() error: %v", err)
	}

	message := []byte("block header payload for signing test")

	sig, err := e.Sign(message, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign() returned empty signature")
	}

	if !e.Verify(message, sig, pub) {
		t.Error("Verify() returned false for a valid signature")
	}
}

// TestTraditionalEngine_Verify_WrongKey ensures verification fails when the
// public key does not match the signing key.
func TestTraditionalEngine_Verify_WrongKey(t *testing.T) {
	e := NewTraditionalEngine()

	_, priv1, _ := e.GenerateAsymmetricKeys()
	pub2, _, _ := e.GenerateAsymmetricKeys() // a different key pair

	message := []byte("some message")
	sig, err := e.Sign(message, priv1)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if e.Verify(message, sig, pub2) {
		t.Error("Verify() returned true for a mismatched public key")
	}
}

// TestTraditionalEngine_Verify_TamperedMessage ensures verification fails when
// the message is altered after signing.
func TestTraditionalEngine_Verify_TamperedMessage(t *testing.T) {
	e := NewTraditionalEngine()
	pub, priv, _ := e.GenerateAsymmetricKeys()

	original := []byte("original message")
	sig, err := e.Sign(original, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	tampered := []byte("tampered message")
	if e.Verify(tampered, sig, pub) {
		t.Error("Verify() returned true for a tampered message")
	}
}

// TestTraditionalEngine_Verify_TamperedSignature ensures verification fails
// when the signature bytes are altered.
func TestTraditionalEngine_Verify_TamperedSignature(t *testing.T) {
	e := NewTraditionalEngine()
	pub, priv, _ := e.GenerateAsymmetricKeys()

	message := []byte("message")
	sig, err := e.Sign(message, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	// Flip a byte in the middle of the signature.
	corrupted := make([]byte, len(sig))
	copy(corrupted, sig)
	corrupted[len(corrupted)/2] ^= 0xFF

	if e.Verify(message, corrupted, pub) {
		t.Error("Verify() returned true for a corrupted signature")
	}
}

// TestTraditionalEngine_GenerateKEMKeys verifies X25519 key pair dimensions.
func TestTraditionalEngine_GenerateKEMKeys(t *testing.T) {
	e := NewTraditionalEngine()
	pub, priv, err := e.GenerateKEMKeys()
	if err != nil {
		t.Fatalf("GenerateKEMKeys() error: %v", err)
	}

	// X25519 keys are always 32 bytes.
	if len(pub) != 32 {
		t.Errorf("KEM public key length = %d, want 32", len(pub))
	}
	if len(priv) != 32 {
		t.Errorf("KEM private key length = %d, want 32", len(priv))
	}
}

// TestTraditionalEngine_EncapDecap_RoundTrip is the KEM correctness test:
// both sides must derive the same shared secret.
func TestTraditionalEngine_EncapDecap_RoundTrip(t *testing.T) {
	e := NewTraditionalEngine()

	// Node B generates a static KEM key pair and shares its public key.
	nodeBPub, nodeBPriv, err := e.GenerateKEMKeys()
	if err != nil {
		t.Fatalf("GenerateKEMKeys() error: %v", err)
	}

	// Node A encapsulates against Node B's public key.
	ciphertext, sharedA, err := e.Encapsulate(nodeBPub)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("Encapsulate() returned empty ciphertext")
	}
	if len(sharedA) == 0 {
		t.Fatal("Encapsulate() returned empty shared secret")
	}

	// Node B decapsulates using its private key and Node A's ephemeral pubkey.
	sharedB, err := e.Decapsulate(ciphertext, nodeBPriv)
	if err != nil {
		t.Fatalf("Decapsulate() error: %v", err)
	}

	if !bytes.Equal(sharedA, sharedB) {
		t.Errorf("shared secrets do not match:\n  A: %x\n  B: %x", sharedA, sharedB)
	}
}

// TestTraditionalEngine_Decapsulate_WrongKey ensures that decapsulation with
// the wrong private key produces a different (incorrect) shared secret.
func TestTraditionalEngine_Decapsulate_WrongKey(t *testing.T) {
	e := NewTraditionalEngine()

	nodeBPub, _, _ := e.GenerateKEMKeys()
	_, wrongPriv, _ := e.GenerateKEMKeys() // unrelated private key

	ciphertext, sharedA, err := e.Encapsulate(nodeBPub)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Decapsulation with the wrong key won't error (DH always produces a
	// result), but the secret must differ.
	sharedWrong, err := e.Decapsulate(ciphertext, wrongPriv)
	if err != nil {
		t.Fatalf("Decapsulate() unexpected error: %v", err)
	}

	if bytes.Equal(sharedA, sharedWrong) {
		t.Error("wrong private key produced the same shared secret — this is a critical failure")
	}
}
