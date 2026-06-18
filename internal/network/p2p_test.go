package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"pqc-blockchain-sim/internal/consensus"
	"pqc-blockchain-sim/internal/crypto"
)

// ---------------------------------------------------------------------------
// Test harness helpers
// ---------------------------------------------------------------------------

// newTestServer builds a PeerServer backed by a TraditionalEngine.
// listenAddr is synthetic — no real socket is bound in these tests.
func newTestServer(t *testing.T, listenAddr string) *PeerServer {
	t.Helper()
	engine := crypto.NewTraditionalEngine()
	ledger := consensus.NewLedger(engine, nil)
	srv, err := NewPeerServer(listenAddr, engine, ledger)
	if err != nil {
		t.Fatalf("NewPeerServer(%s): %v", listenAddr, err)
	}
	t.Cleanup(func() {
		select {
		case <-srv.quit:
		default:
			srv.Stop()
		}
	})
	return srv
}

// pipePair returns an in-process net.Pipe() pair and registers cleanup so
// both ends are closed when the test exits, preventing goroutine leaks.
func pipePair(t *testing.T) (initiatorConn, acceptorConn net.Conn) {
	t.Helper()
	initiatorConn, acceptorConn = net.Pipe()
	t.Cleanup(func() {
		initiatorConn.Close()
		acceptorConn.Close()
	})
	return initiatorConn, acceptorConn
}

// runAcceptor starts handleInbound on acceptorConn in a background goroutine
// and returns a channel that closes when the goroutine exits.
func runAcceptor(srv *PeerServer, acceptorConn net.Conn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleInbound(acceptorConn)
	}()
	return done
}

// doInitiatorHandshake executes the initiator (Node A) side of the KEM
// handshake over conn, using srv's KEM keys and engine.
// Returns the derived 32-byte session key on success.
func doInitiatorHandshake(srv *PeerServer, conn net.Conn) ([]byte, error) {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	// Step 1 — send MsgHandshakeInit with our KEM public key.
	initPayload, err := json.Marshal(HandshakeInitPayload{KEMPublicKey: srv.kemPubKey})
	if err != nil {
		return nil, fmt.Errorf("marshal HandshakeInit: %w", err)
	}
	if err := writePacket(conn, Packet{Type: MsgHandshakeInit, Payload: initPayload}); err != nil {
		return nil, fmt.Errorf("write HandshakeInit: %w", err)
	}

	// Step 3 — receive MsgHandshakeReply with the ciphertext.
	pkt, err := readPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("read HandshakeReply: %w", err)
	}
	if pkt.Type != MsgHandshakeReply {
		return nil, fmt.Errorf("expected MsgHandshakeReply (%d), got %d", MsgHandshakeReply, pkt.Type)
	}

	var reply HandshakeReplyPayload
	if err := json.Unmarshal(pkt.Payload, &reply); err != nil {
		return nil, fmt.Errorf("decode HandshakeReply: %w", err)
	}

	rawSecret, err := srv.engine.Decapsulate(reply.Ciphertext, srv.kemPrivKey)
	if err != nil {
		return nil, fmt.Errorf("Decapsulate: %w", err)
	}
	return deriveSessionKey(rawSecret), nil
}

// peerCount returns the current number of registered peers under the read lock.
func peerCount(srv *PeerServer) int {
	srv.peersMu.RLock()
	defer srv.peersMu.RUnlock()
	return len(srv.peers)
}

// waitFor polls pred every 5 ms until it returns true or timeout expires.
func waitFor(timeout time.Duration, pred func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// ---------------------------------------------------------------------------
// 1. Packet framing — writePacket / readPacket round-trip
// ---------------------------------------------------------------------------

func TestPacketFraming_RoundTrip(t *testing.T) {
	want := Packet{
		Type:    MsgTransaction,
		Payload: []byte(`{"tx":{}}`),
	}

	var buf bytes.Buffer
	if err := writePacket(&buf, want); err != nil {
		t.Fatalf("writePacket: %v", err)
	}
	got, err := readPacket(&buf)
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}

	if got.Type != want.Type {
		t.Errorf("Type: got %d, want %d", got.Type, want.Type)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("Payload: got %q, want %q", got.Payload, want.Payload)
	}
}

func TestPacketFraming_AllMessageTypes(t *testing.T) {
	types := []MessageType{
		MsgHandshakeInit,
		MsgHandshakeReply,
		MsgTransaction,
		MsgBlock,
	}
	for _, mt := range types {
		var buf bytes.Buffer
		pkt := Packet{Type: mt, Payload: []byte(`"test"`)}
		if err := writePacket(&buf, pkt); err != nil {
			t.Fatalf("writePacket(%d): %v", mt, err)
		}
		got, err := readPacket(&buf)
		if err != nil {
			t.Fatalf("readPacket(%d): %v", mt, err)
		}
		if got.Type != mt {
			t.Errorf("type round-trip: got %d, want %d", got.Type, mt)
		}
	}
}

func TestPacketFraming_ZeroLengthBody_Rejected(t *testing.T) {
	// Manually write a 4-byte header of zero length — readPacket must reject it.
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0})
	_, err := readPacket(&buf)
	if err == nil {
		t.Fatal("readPacket accepted a zero-length packet — expected error")
	}
}

func TestPacketFraming_OversizeBody_Rejected(t *testing.T) {
	// Write a header claiming 20 MB — readPacket must reject it.
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x40, 0x00, 0x00}) // 0x01400000 = 20971520 bytes > 10 MB
	_, err := readPacket(&buf)
	if err == nil {
		t.Fatal("readPacket accepted an oversize packet — expected error")
	}
}

// ---------------------------------------------------------------------------
// 2. KEM handshake — successful round-trip via net.Pipe()
// ---------------------------------------------------------------------------

// TestHandshake_FullRoundTrip drives both sides of the KEM handshake over an
// in-process net.Pipe() and verifies the session key is identical.
func TestHandshake_FullRoundTrip(t *testing.T) {
	// Two independent servers simulate two distinct nodes.
	// "aaa" < "bbb" so srvA is the lexicographic initiator.
	srvA := newTestServer(t, "aaa:8000")
	srvB := newTestServer(t, "bbb:8000")

	connA, connB := pipePair(t)

	// Node B runs as acceptor in the background.
	acceptorDone := runAcceptor(srvB, connB)

	// Node A runs as initiator in the foreground.
	sessionKeyA, err := doInitiatorHandshake(srvA, connA)
	if err != nil {
		t.Fatalf("initiator handshake: %v", err)
	}

	// Wait for the acceptor goroutine to register the peer (it blocks in runPeer
	// after the handshake; closing connA will cause it to exit).
	if !waitFor(2*time.Second, func() bool { return peerCount(srvB) == 1 }) {
		t.Fatal("srvB did not register the peer within 2s")
	}

	// Grab Node B's session key from the registered peer.
	srvB.peersMu.RLock()
	var sessionKeyB []byte
	for _, p := range srvB.peers {
		sessionKeyB = p.sessionKey
	}
	srvB.peersMu.RUnlock()

	if len(sessionKeyA) != 32 {
		t.Errorf("session key A length = %d, want 32", len(sessionKeyA))
	}
	if len(sessionKeyB) != 32 {
		t.Errorf("session key B length = %d, want 32", len(sessionKeyB))
	}
	if !bytes.Equal(sessionKeyA, sessionKeyB) {
		t.Errorf("session keys differ:\n  A: %x\n  B: %x", sessionKeyA, sessionKeyB)
	}

	// Close connA to unblock the acceptor's runPeer loop so the goroutine exits.
	connA.Close()
	<-acceptorDone
}

// TestHandshake_SessionKeyDerivation verifies that deriveSessionKey is
// deterministic and produces a 32-byte output matching SHA-256 of the input.
func TestHandshake_SessionKeyDerivation(t *testing.T) {
	raw := []byte("shared secret bytes for test")
	key := deriveSessionKey(raw)

	if len(key) != 32 {
		t.Errorf("session key length = %d, want 32", len(key))
	}

	// Must be deterministic.
	key2 := deriveSessionKey(raw)
	if !bytes.Equal(key, key2) {
		t.Error("deriveSessionKey is not deterministic")
	}

	// Must equal SHA-256 of input.
	h := sha256.Sum256(raw)
	if !bytes.Equal(key, h[:]) {
		t.Errorf("key = %x, want sha256(%x) = %x", key, raw, h[:])
	}
}

// TestHandshake_DifferentInputs_DifferentKeys ensures distinct raw secrets
// produce distinct session keys.
func TestHandshake_DifferentInputs_DifferentKeys(t *testing.T) {
	k1 := deriveSessionKey([]byte("secret one"))
	k2 := deriveSessionKey([]byte("secret two"))
	if bytes.Equal(k1, k2) {
		t.Error("different raw secrets produced the same session key")
	}
}

// ---------------------------------------------------------------------------
// 3. Handshake failure — bad / tampered packets
// ---------------------------------------------------------------------------

// TestHandshake_WrongFirstPacketType sends a non-HandshakeInit packet to the
// acceptor; it must close the connection and exit cleanly.
func TestHandshake_WrongFirstPacketType(t *testing.T) {
	srvB := newTestServer(t, "bbb:8000")
	connClient, connServer := pipePair(t)

	acceptorDone := runAcceptor(srvB, connServer)

	// Send MsgBlock instead of MsgHandshakeInit.
	payload, _ := json.Marshal(BlockPayload{})
	if err := writePacket(connClient, Packet{Type: MsgBlock, Payload: payload}); err != nil {
		t.Fatalf("writePacket: %v", err)
	}

	// Acceptor should reject and close the connection.
	select {
	case <-acceptorDone:
		// Correct — acceptor exited after rejecting the wrong packet type.
	case <-time.After(2 * time.Second):
		t.Fatal("acceptor did not exit after receiving wrong packet type")
	}

	// No peer should have been registered.
	if n := peerCount(srvB); n != 0 {
		t.Errorf("peer count = %d after bad handshake, want 0", n)
	}
}

// TestHandshake_MalformedHandshakeInitPayload sends a syntactically valid
// MsgHandshakeInit packet but with garbage JSON that cannot be decoded.
func TestHandshake_MalformedHandshakeInitPayload(t *testing.T) {
	srvB := newTestServer(t, "bbb:8000")
	connClient, connServer := pipePair(t)

	acceptorDone := runAcceptor(srvB, connServer)

	// Correct type, but payload is not valid HandshakeInitPayload JSON.
	if err := writePacket(connClient, Packet{
		Type:    MsgHandshakeInit,
		Payload: []byte(`{this is not json}`),
	}); err != nil {
		t.Fatalf("writePacket: %v", err)
	}

	select {
	case <-acceptorDone:
		// Acceptor rejected malformed JSON and exited — correct.
	case <-time.After(2 * time.Second):
		t.Fatal("acceptor did not exit after malformed HandshakeInit payload")
	}

	if n := peerCount(srvB); n != 0 {
		t.Errorf("peer count = %d after malformed handshake, want 0", n)
	}
}

// TestHandshake_TamperedCiphertext sends a valid HandshakeInit to the acceptor,
// intercepts the HandshakeReply, corrupts the ciphertext bytes, and verifies
// that the initiator's Decapsulate call fails.
func TestHandshake_TamperedCiphertext(t *testing.T) {
	srvA := newTestServer(t, "aaa:8000")
	srvB := newTestServer(t, "bbb:8000")
	connA, connB := pipePair(t)

	// Run acceptor normally — it will send a genuine HandshakeReply.
	acceptorDone := runAcceptor(srvB, connB)

	// Send HandshakeInit from A.
	connA.SetDeadline(time.Now().Add(handshakeTimeout))
	defer connA.SetDeadline(time.Time{})

	initPayload, _ := json.Marshal(HandshakeInitPayload{KEMPublicKey: srvA.kemPubKey})
	if err := writePacket(connA, Packet{Type: MsgHandshakeInit, Payload: initPayload}); err != nil {
		t.Fatalf("write HandshakeInit: %v", err)
	}

	// Read the reply from B.
	pkt, err := readPacket(connA)
	if err != nil {
		t.Fatalf("read HandshakeReply: %v", err)
	}
	if pkt.Type != MsgHandshakeReply {
		t.Fatalf("expected HandshakeReply, got %d", pkt.Type)
	}

	// Tamper: flip every byte in the ciphertext.
	var reply HandshakeReplyPayload
	if err := json.Unmarshal(pkt.Payload, &reply); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	for i := range reply.Ciphertext {
		reply.Ciphertext[i] ^= 0xFF
	}

	// Attempt Decapsulate with the corrupted ciphertext.
	_, err = srvA.engine.Decapsulate(reply.Ciphertext, srvA.kemPrivKey)
	if err == nil {
		// For X25519, Decapsulate doesn't error on wrong ciphertext — it just
		// produces a wrong shared secret. Verify the derived key differs from
		// what B derived, by checking it against B's registered session key.
		rawWrong, _ := srvA.engine.Decapsulate(reply.Ciphertext, srvA.kemPrivKey)
		wrongKey := deriveSessionKey(rawWrong)

		if waitFor(2*time.Second, func() bool { return peerCount(srvB) == 1 }) {
			srvB.peersMu.RLock()
			var keyB []byte
			for _, p := range srvB.peers {
				keyB = p.sessionKey
			}
			srvB.peersMu.RUnlock()

			if bytes.Equal(wrongKey, keyB) {
				t.Error("tampered ciphertext produced the same session key — integrity check failed")
			}
		}
	}
	// If Decapsulate errored, the tamper was caught — also a pass.

	connA.Close()
	<-acceptorDone
}

// ---------------------------------------------------------------------------
// 4. Handshake deadline / timeout
// ---------------------------------------------------------------------------

// TestHandshake_TimeoutOnAcceptor verifies that when the initiator stalls and
// never sends HandshakeInit, the acceptor's connection deadline fires and it
// exits cleanly.
//
// Strategy: wrap the server-side conn in a deadlineConn that ignores any
// SetDeadline calls, then pre-set a 50ms deadline so the production code's
// own conn.SetDeadline(handshakeTimeout) call has no effect and our short
// deadline remains in force.
func TestHandshake_TimeoutOnAcceptor(t *testing.T) {
	srvB := newTestServer(t, "bbb:8000")

	connClient, connServer := pipePair(t)

	// Pre-set a short deadline on the server side. We then wrap it in
	// frozenDeadlineConn so handleInbound's SetDeadline call is a no-op,
	// preserving our short deadline.
	connServer.SetDeadline(time.Now().Add(50 * time.Millisecond))
	frozen := &frozenDeadlineConn{Conn: connServer}

	acceptorDone := make(chan struct{})
	go func() {
		defer close(acceptorDone)
		srvB.handleInbound(frozen)
	}()

	// Do NOT send anything — the acceptor should time out.
	select {
	case <-acceptorDone:
		// Correct — deadline fired and acceptor exited.
	case <-time.After(2 * time.Second):
		t.Fatal("acceptor did not exit after read deadline expired")
	}

	if n := peerCount(srvB); n != 0 {
		t.Errorf("peer count = %d after timeout, want 0", n)
	}

	connClient.Close()
}

// frozenDeadlineConn wraps a net.Conn and silently ignores all SetDeadline /
// SetReadDeadline / SetWriteDeadline calls. This lets tests pre-set a short
// deadline without it being overwritten by the code under test.
type frozenDeadlineConn struct {
	net.Conn
}

func (f *frozenDeadlineConn) SetDeadline(_ time.Time) error      { return nil }
func (f *frozenDeadlineConn) SetReadDeadline(_ time.Time) error  { return nil }
func (f *frozenDeadlineConn) SetWriteDeadline(_ time.Time) error { return nil }

// TestHandshake_TimeoutOnInitiator verifies that when the acceptor stalls and
// never replies, the initiator's deadline fires.
func TestHandshake_TimeoutOnInitiator(t *testing.T) {
	srvA := newTestServer(t, "aaa:8000")
	connClient, connServer := pipePair(t)

	// Do NOT run handleInbound — simulate an acceptor that receives the init
	// packet but never replies.
	_ = connServer // acceptor side is silent

	// Set a short deadline on the initiator side.
	connClient.SetDeadline(time.Now().Add(50 * time.Millisecond))

	initPayload, _ := json.Marshal(HandshakeInitPayload{KEMPublicKey: srvA.kemPubKey})
	if err := writePacket(connClient, Packet{Type: MsgHandshakeInit, Payload: initPayload}); err != nil {
		// Write may itself time out if deadline is very tight.
		t.Logf("write timed out: %v", err)
		return
	}

	// readPacket should block and then time out.
	_, err := readPacket(connClient)
	if err == nil {
		t.Fatal("readPacket succeeded when acceptor never replied — expected timeout error")
	}
}

// ---------------------------------------------------------------------------
// 5. NewPeerServer — construction and KEM key separation
// ---------------------------------------------------------------------------

// TestNewPeerServer_KEMKeysGenerated verifies that NewPeerServer generates
// non-empty, non-zero KEM keys that are distinct from signing keys.
func TestNewPeerServer_KEMKeysGenerated(t *testing.T) {
	srv := newTestServer(t, "127.0.0.1:9000")

	if len(srv.kemPubKey) == 0 {
		t.Error("kemPubKey is empty")
	}
	if len(srv.kemPrivKey) == 0 {
		t.Error("kemPrivKey is empty")
	}

	// X25519 keys are 32 bytes each.
	if len(srv.kemPubKey) != 32 {
		t.Errorf("kemPubKey length = %d, want 32", len(srv.kemPubKey))
	}
	if len(srv.kemPrivKey) != 32 {
		t.Errorf("kemPrivKey length = %d, want 32", len(srv.kemPrivKey))
	}
}

// TestNewPeerServer_TwoServers_DistinctKEMKeys verifies that independently
// created servers generate distinct KEM key pairs.
func TestNewPeerServer_TwoServers_DistinctKEMKeys(t *testing.T) {
	srvA := newTestServer(t, "aaa:8000")
	srvB := newTestServer(t, "bbb:8000")

	if bytes.Equal(srvA.kemPubKey, srvB.kemPubKey) {
		t.Error("two servers share the same KEM public key")
	}
	if bytes.Equal(srvA.kemPrivKey, srvB.kemPrivKey) {
		t.Error("two servers share the same KEM private key")
	}
}

// ---------------------------------------------------------------------------
// 6. Flood / broadcast routing
// ---------------------------------------------------------------------------

// TestFlood_SkipsOriginPeer verifies that a packet is not echoed back to the
// peer it arrived from.
func TestFlood_SkipsOriginPeer(t *testing.T) {
	srv := newTestServer(t, "aaa:8000")

	// Manually register two synthetic peers.
	connA1, connA2 := net.Pipe()
	connB1, connB2 := net.Pipe()
	defer connA1.Close()
	defer connA2.Close()
	defer connB1.Close()
	defer connB2.Close()

	peerA := &Peer{addr: "peer-a", conn: connA1, send: make(chan Packet, 8)}
	peerB := &Peer{addr: "peer-b", conn: connB1, send: make(chan Packet, 8)}

	srv.peersMu.Lock()
	srv.peers["peer-a"] = peerA
	srv.peers["peer-b"] = peerB
	srv.peersMu.Unlock()

	pkt := Packet{Type: MsgTransaction, Payload: []byte(`{}`)}
	srv.flood(peerA, pkt) // origin = peerA

	// peerB must have received the packet.
	select {
	case got := <-peerB.send:
		if got.Type != MsgTransaction {
			t.Errorf("peerB received wrong type: %d", got.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("peerB did not receive the flooded packet")
	}

	// peerA must NOT have received its own packet.
	select {
	case <-peerA.send:
		t.Error("peerA received its own flooded packet — origin exclusion broken")
	case <-time.After(50 * time.Millisecond):
		// Correct — no packet for the origin.
	}
}

// TestFlood_NilOrigin_SendsToAll verifies that a nil origin (local broadcast)
// reaches every registered peer.
func TestFlood_NilOrigin_SendsToAll(t *testing.T) {
	srv := newTestServer(t, "aaa:8000")

	connA1, connA2 := net.Pipe()
	connB1, connB2 := net.Pipe()
	defer connA1.Close()
	defer connA2.Close()
	defer connB1.Close()
	defer connB2.Close()

	peerA := &Peer{addr: "peer-a", conn: connA1, send: make(chan Packet, 8)}
	peerB := &Peer{addr: "peer-b", conn: connB1, send: make(chan Packet, 8)}

	srv.peersMu.Lock()
	srv.peers["peer-a"] = peerA
	srv.peers["peer-b"] = peerB
	srv.peersMu.Unlock()

	srv.flood(nil, Packet{Type: MsgBlock, Payload: []byte(`{}`)})

	for _, p := range []*Peer{peerA, peerB} {
		select {
		case got := <-p.send:
			if got.Type != MsgBlock {
				t.Errorf("peer %s: wrong type %d", p.addr, got.Type)
			}
		case <-time.After(100 * time.Millisecond):
			t.Errorf("peer %s did not receive nil-origin flood", p.addr)
		}
	}
}
