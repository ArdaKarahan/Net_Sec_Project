package crypto

import (
	"errors"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// PQCEngine implements CryptoEngine using NIST post-quantum algorithms via
// liboqs. It is configured with a KEM algorithm (for key encapsulation) and a
// signature algorithm (for signing/verification) independently.
type PQCEngine struct {
	name    string
	kemName string
	sigName string
}

// NewKyberDilithiumEngine returns a PQCEngine configured for
// Kyber-512 (KEM) + ML-DSA-44 / Dilithium2 (signatures) — PQC Model Alpha.
// The NIST-standardised name for Dilithium2 in liboqs >= 0.10 is "ML-DSA-44".
func NewKyberDilithiumEngine() *PQCEngine {
	return &PQCEngine{
		name:    "PQC (Kyber512 + Dilithium2)",
		kemName: "Kyber512",
		sigName: "ML-DSA-44",
	}
}

// NewKyberFalconEngine returns a PQCEngine configured for
// Kyber-512 (KEM) + Falcon-512 (signatures) — PQC Model Beta.
func NewKyberFalconEngine() *PQCEngine {
	return &PQCEngine{
		name:    "PQC (Kyber512 + Falcon512)",
		kemName: "Kyber512",
		sigName: "Falcon-512",
	}
}

func (p *PQCEngine) Name() string {
	return p.name
}

// GenerateAsymmetricKeys generates a key pair for the configured signature
// scheme. Returns (sigPublicKey, sigPrivateKey, error).
// Note: KEM keys are separate and generated via GenerateKEMKeys.
func (p *PQCEngine) GenerateAsymmetricKeys() (pubKey []byte, privKey []byte, err error) {
	var signer oqs.Signature
	if err = signer.Init(p.sigName, nil); err != nil {
		return nil, nil, err
	}

	pubKey, err = signer.GenerateKeyPair()
	if err != nil {
		signer.Clean()
		return nil, nil, err
	}

	// Export the secret key BEFORE Clean() zeroes it.
	exported := signer.ExportSecretKey()
	privKey = make([]byte, len(exported))
	copy(privKey, exported)

	signer.Clean()
	return pubKey, privKey, nil
}

// GenerateKEMKeys generates a key pair for the configured KEM algorithm.
// The returned keys are used in Encapsulate/Decapsulate, not signing.
func (p *PQCEngine) GenerateKEMKeys() (pubKey []byte, privKey []byte, err error) {
	var kem oqs.KeyEncapsulation
	if err = kem.Init(p.kemName, nil); err != nil {
		return nil, nil, err
	}

	pubKey, err = kem.GenerateKeyPair()
	if err != nil {
		kem.Clean()
		return nil, nil, err
	}

	// Export the secret key BEFORE Clean() zeroes it.
	exported := kem.ExportSecretKey()
	privKey = make([]byte, len(exported))
	copy(privKey, exported)

	kem.Clean()
	return pubKey, privKey, nil
}

// Sign signs the raw message bytes using the configured PQC signature scheme.
// privKey must be the secret key produced by GenerateAsymmetricKeys.
func (p *PQCEngine) Sign(message []byte, privKey []byte) ([]byte, error) {
	if len(privKey) == 0 {
		return nil, errors.New("pqc: Sign: private key is empty")
	}

	var signer oqs.Signature
	// Pass privKey directly into Init so Sign() can use it immediately.
	if err := signer.Init(p.sigName, privKey); err != nil {
		return nil, err
	}
	defer signer.Clean()

	return signer.Sign(message)
}

// Verify checks the signature against message using the provided public key.
// Returns false on any mismatch or error.
func (p *PQCEngine) Verify(message []byte, signature []byte, pubKey []byte) bool {
	var signer oqs.Signature
	if err := signer.Init(p.sigName, nil); err != nil {
		return false
	}
	defer signer.Clean()

	valid, err := signer.Verify(message, signature, pubKey)
	if err != nil {
		return false
	}
	return valid
}

// Encapsulate generates a shared secret and its corresponding ciphertext using
// the peer's KEM public key. The peer decapsulates with their private key.
func (p *PQCEngine) Encapsulate(peerPubKey []byte) (ciphertext []byte, sharedSecret []byte, err error) {
	var kem oqs.KeyEncapsulation
	if err = kem.Init(p.kemName, nil); err != nil {
		return nil, nil, err
	}
	defer kem.Clean()

	return kem.EncapSecret(peerPubKey)
}

// Decapsulate recovers the shared secret from ciphertext using the local KEM
// private key produced by GenerateKEMKeys.
func (p *PQCEngine) Decapsulate(ciphertext []byte, privKey []byte) ([]byte, error) {
	if len(privKey) == 0 {
		return nil, errors.New("pqc: Decapsulate: private key is empty")
	}

	var kem oqs.KeyEncapsulation
	// Init with the private key so DecapSecret can use it.
	if err := kem.Init(p.kemName, privKey); err != nil {
		return nil, err
	}
	defer kem.Clean()

	return kem.DecapSecret(ciphertext)
}
