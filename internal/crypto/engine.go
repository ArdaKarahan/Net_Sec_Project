package crypto

// CryptoEngine handles all cryptographic abstractions for the blockchain node.
type CryptoEngine interface {
	// Name returns the identifier of the cryptographic suite
	Name() string

	// --- Key Generation ---
	GenerateAsymmetricKeys() (pubKey []byte, privKey []byte, err error)

	// --- Digital Signatures ---
	Sign(message []byte, privKey []byte) (signature []byte, err error)
	Verify(message []byte, signature []byte, pubKey []byte) bool

	// --- Key Encapsulation Mechanism (KEM) ---
	Encapsulate(peerPubKey []byte) (ciphertext []byte, sharedSecret []byte, err error)
	Decapsulate(ciphertext []byte, privKey []byte) (sharedSecret []byte, err error)
}
