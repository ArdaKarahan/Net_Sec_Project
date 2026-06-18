package crypto

import (
	"bytes"
	"testing"
)

// --- Factory / Name tests ---

func TestNewKyberDilithiumEngine_Name(t *testing.T) {
	e := NewKyberDilithiumEngine()
	want := "PQC (Kyber512 + Dilithium2)"
	if got := e.Name(); got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestNewKyberFalconEngine_Name(t *testing.T) {
	e := NewKyberFalconEngine()
	want := "PQC (Kyber512 + Falcon512)"
	if got := e.Name(); got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

// --- Dilithium2 suite tests ---

func TestPQCEngine_Dilithium_GenerateAsymmetricKeys(t *testing.T) {
	e := NewKyberDilithiumEngine()

	pub, priv, err := e.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("GenerateAsymmetricKeys() error: %v", err)
	}
	if len(pub) == 0 {
		t.Error("public key is empty")
	}
	if len(priv) == 0 {
		t.Error("private key is empty")
	}

	// Two calls must produce distinct keys.
	pub2, priv2, err := e.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("second GenerateAsymmetricKeys() error: %v", err)
	}
	if bytes.Equal(pub, pub2) {
		t.Error("two generated public keys are identical")
	}
	if bytes.Equal(priv, priv2) {
		t.Error("two generated private keys are identical")
	}
}

func TestPQCEngine_Dilithium_SignVerify_RoundTrip(t *testing.T) {
	e := NewKyberDilithiumEngine()

	pub, priv, err := e.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("GenerateAsymmetricKeys() error: %v", err)
	}

	message := []byte("dilithium2 signing test message")

	sig, err := e.Sign(message, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign() returned empty signature")
	}

	if !e.Verify(message, sig, pub) {
		t.Error("Verify() returned false for a valid Dilithium2 signature")
	}
}

func TestPQCEngine_Dilithium_Verify_WrongKey(t *testing.T) {
	e := NewKyberDilithiumEngine()

	_, priv1, _ := e.GenerateAsymmetricKeys()
	pub2, _, _ := e.GenerateAsymmetricKeys()

	sig, err := e.Sign([]byte("message"), priv1)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if e.Verify([]byte("message"), sig, pub2) {
		t.Error("Verify() returned true for a mismatched Dilithium2 key")
	}
}

func TestPQCEngine_Dilithium_Verify_TamperedMessage(t *testing.T) {
	e := NewKyberDilithiumEngine()

	pub, priv, _ := e.GenerateAsymmetricKeys()
	sig, err := e.Sign([]byte("original"), priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if e.Verify([]byte("tampered"), sig, pub) {
		t.Error("Verify() returned true for a tampered message (Dilithium2)")
	}
}

// --- Falcon-512 suite tests ---

func TestPQCEngine_Falcon_GenerateAsymmetricKeys(t *testing.T) {
	e := NewKyberFalconEngine()

	pub, priv, err := e.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("GenerateAsymmetricKeys() error: %v", err)
	}
	if len(pub) == 0 {
		t.Error("public key is empty")
	}
	if len(priv) == 0 {
		t.Error("private key is empty")
	}
}

func TestPQCEngine_Falcon_SignVerify_RoundTrip(t *testing.T) {
	e := NewKyberFalconEngine()

	pub, priv, err := e.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("GenerateAsymmetricKeys() error: %v", err)
	}

	message := []byte("falcon-512 signing test message")

	sig, err := e.Sign(message, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if !e.Verify(message, sig, pub) {
		t.Error("Verify() returned false for a valid Falcon-512 signature")
	}
}

func TestPQCEngine_Falcon_Verify_WrongKey(t *testing.T) {
	e := NewKyberFalconEngine()

	_, priv1, _ := e.GenerateAsymmetricKeys()
	pub2, _, _ := e.GenerateAsymmetricKeys()

	sig, err := e.Sign([]byte("message"), priv1)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if e.Verify([]byte("message"), sig, pub2) {
		t.Error("Verify() returned true for a mismatched Falcon-512 key")
	}
}

// --- Kyber-512 KEM tests (same KEM for both engines, test with Dilithium variant) ---

func TestPQCEngine_GenerateKEMKeys(t *testing.T) {
	e := NewKyberDilithiumEngine()

	pub, priv, err := e.GenerateKEMKeys()
	if err != nil {
		t.Fatalf("GenerateKEMKeys() error: %v", err)
	}
	if len(pub) == 0 {
		t.Error("KEM public key is empty")
	}
	if len(priv) == 0 {
		t.Error("KEM private key is empty")
	}

	pub2, priv2, err := e.GenerateKEMKeys()
	if err != nil {
		t.Fatalf("second GenerateKEMKeys() error: %v", err)
	}
	if bytes.Equal(pub, pub2) {
		t.Error("two generated KEM public keys are identical")
	}
	if bytes.Equal(priv, priv2) {
		t.Error("two generated KEM private keys are identical")
	}
}

func TestPQCEngine_EncapDecap_RoundTrip_Dilithium(t *testing.T) {
	e := NewKyberDilithiumEngine()
	testKEMRoundTrip(t, e)
}

func TestPQCEngine_EncapDecap_RoundTrip_Falcon(t *testing.T) {
	e := NewKyberFalconEngine()
	testKEMRoundTrip(t, e)
}

// testKEMRoundTrip is a shared helper that verifies the KEM round-trip for any
// PQCEngine configuration: both parties must arrive at the same shared secret.
func testKEMRoundTrip(t *testing.T, e *PQCEngine) {
	t.Helper()

	// Node B generates a static KEM key pair.
	nodeBPub, nodeBPriv, err := e.GenerateKEMKeys()
	if err != nil {
		t.Fatalf("[%s] GenerateKEMKeys() error: %v", e.Name(), err)
	}

	// Node A encapsulates against Node B's public key.
	ciphertext, sharedA, err := e.Encapsulate(nodeBPub)
	if err != nil {
		t.Fatalf("[%s] Encapsulate() error: %v", e.Name(), err)
	}
	if len(ciphertext) == 0 {
		t.Fatalf("[%s] Encapsulate() returned empty ciphertext", e.Name())
	}
	if len(sharedA) == 0 {
		t.Fatalf("[%s] Encapsulate() returned empty shared secret", e.Name())
	}

	// Node B decapsulates with its private key.
	sharedB, err := e.Decapsulate(ciphertext, nodeBPriv)
	if err != nil {
		t.Fatalf("[%s] Decapsulate() error: %v", e.Name(), err)
	}

	if !bytes.Equal(sharedA, sharedB) {
		t.Errorf("[%s] shared secrets do not match:\n  A: %x\n  B: %x",
			e.Name(), sharedA, sharedB)
	}
}

// TestPQCEngine_SeparateKeySpaces verifies that signing keys and KEM keys are
// independent — a signing private key must not work as a KEM decapsulation key.
func TestPQCEngine_SeparateKeySpaces(t *testing.T) {
	e := NewKyberDilithiumEngine()

	kemPub, _, err := e.GenerateKEMKeys()
	if err != nil {
		t.Fatalf("GenerateKEMKeys() error: %v", err)
	}

	_, sigPriv, err := e.GenerateAsymmetricKeys()
	if err != nil {
		t.Fatalf("GenerateAsymmetricKeys() error: %v", err)
	}

	ciphertext, _, err := e.Encapsulate(kemPub)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Passing a signature private key to Decapsulate must return an error
	// because its length won't match the expected KEM secret key length.
	_, err = e.Decapsulate(ciphertext, sigPriv)
	if err == nil {
		t.Error("Decapsulate() succeeded with a signing key — key spaces are not properly separated")
	}
}

// TestPQCEngine_InterfaceCompliance ensures both engines satisfy CryptoEngine
// at compile time. This is a compile-time check; no runtime assertion needed.
var _ CryptoEngine = (*PQCEngine)(nil)
var _ CryptoEngine = (*TraditionalEngine)(nil)
