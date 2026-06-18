// Package network implements the TCP-based peer-to-peer engine for the
// blockchain simulation. It handles:
//   - Listening for and accepting inbound peer connections
//   - Initiating outbound connections with exponential-backoff reconnection
//   - A two-step KEM handshake that derives a shared session key per peer
//   - Flooding validated transactions and blocks to all connected peers
//
// All cryptographic operations delegate to the injected crypto.CryptoEngine.
// All block/transaction validation delegates to the injected consensus.Ledger.
package network

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"pqc-blockchain-sim/internal/consensus"
	"pqc-blockchain-sim/internal/crypto"
)

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------

const (
	// handshakeTimeout is the maximum wall-clock time allowed for the entire
	// KEM handshake to complete. Sized conservatively for high-latency WAN links.
	handshakeTimeout = 10 * time.Second

	// ioTimeout is the per-read/write deadline applied to normal message I/O.
	ioTimeout = 30 * time.Second

	// sendQueueDepth is the number of outbound packets buffered per peer before
	// new packets are dropped (slow-peer protection).
	sendQueueDepth = 64

	// reconnectBase is the starting backoff delay after a peer disconnects.
	reconnectBase = 1 * time.Second

	// reconnectCap is the maximum backoff delay between reconnection attempts.
	reconnectCap = 30 * time.Second
)

// ---------------------------------------------------------------------------
// KEMKeyGenerator — narrow interface for KEM key generation at startup
// ---------------------------------------------------------------------------

// KEMKeyGenerator is satisfied by both TraditionalEngine and PQCEngine.
// It is separate from crypto.CryptoEngine because KEM key generation is a
// one-time startup operation, not part of the per-message engine contract.
type KEMKeyGenerator interface {
	GenerateKEMKeys() (pubKey []byte, privKey []byte, err error)
}

// ---------------------------------------------------------------------------
// Wire protocol — message types and packet framing
// ---------------------------------------------------------------------------

// MessageType is the single-byte discriminator at the front of every Packet.
type MessageType uint8

const (
	MsgHandshakeInit  MessageType = 1 // Initiator → Acceptor: KEM public key
	MsgHandshakeReply MessageType = 2 // Acceptor → Initiator: KEM ciphertext
	MsgTransaction    MessageType = 3 // Any peer → Any peer: broadcast transaction
	MsgBlock          MessageType = 4 // Any peer → Any peer: broadcast block
)

// Packet is the top-level wire envelope. It is serialised as:
//
//	[4-byte big-endian uint32 total length][1-byte MessageType][JSON payload bytes]
type Packet struct {
	Type    MessageType
	Payload []byte // JSON-encoded body; schema depends on Type
}

// HandshakeInitPayload is the body of MsgHandshakeInit.
type HandshakeInitPayload struct {
	KEMPublicKey []byte `json:"kem_public_key"`
}

// HandshakeReplyPayload is the body of MsgHandshakeReply.
type HandshakeReplyPayload struct {
	Ciphertext []byte `json:"ciphertext"`
}

// TransactionPayload is the body of MsgTransaction.
type TransactionPayload struct {
	Tx consensus.Transaction `json:"tx"`
}

// BlockPayload is the body of MsgBlock.
type BlockPayload struct {
	Block consensus.Block `json:"block"`
}

// ---------------------------------------------------------------------------
// Peer — a single active connection
// ---------------------------------------------------------------------------

// Peer represents one connected remote node.
type Peer struct {
	addr         string   // "ip:port" used for dedup and reconnect
	conn         net.Conn
	sessionKey   []byte // SHA-256(rawSharedSecret) — stored for metrics/logging
	send         chan Packet
	handshakeDone bool
}

// ---------------------------------------------------------------------------
// PeerServer
// ---------------------------------------------------------------------------

// PeerServer is the top-level P2P engine. Create one per node with NewPeerServer,
// then call ListenAndServe in a goroutine and ConnectToPeers with the initial
// peer address list.
type PeerServer struct {
	listenAddr string
	engine     crypto.CryptoEngine // for Encapsulate / Decapsulate
	ledger     *consensus.Ledger

	kemPubKey  []byte // this node's static KEM public key
	kemPrivKey []byte // this node's static KEM private key

	peers   map[string]*Peer
	peersMu sync.RWMutex

	// Validated events delivered to the application layer.
	InboundTx    chan consensus.Transaction
	InboundBlock chan consensus.Block

	quit chan struct{}
}

// NewPeerServer creates a PeerServer, generating a fresh KEM key pair for this
// node. The engine must also implement KEMKeyGenerator (both built-in engines do).
func NewPeerServer(
	listenAddr string,
	engine crypto.CryptoEngine,
	ledger *consensus.Ledger,
) (*PeerServer, error) {
	gen, ok := engine.(KEMKeyGenerator)
	if !ok {
		return nil, fmt.Errorf("p2p: engine %T does not implement KEMKeyGenerator", engine)
	}

	kemPub, kemPriv, err := gen.GenerateKEMKeys()
	if err != nil {
		return nil, fmt.Errorf("p2p: generating KEM keys: %w", err)
	}

	return &PeerServer{
		listenAddr:   listenAddr,
		engine:       engine,
		ledger:       ledger,
		kemPubKey:    kemPub,
		kemPrivKey:   kemPriv,
		peers:        make(map[string]*Peer),
		InboundTx:    make(chan consensus.Transaction, 256),
		InboundBlock: make(chan consensus.Block, 64),
		quit:         make(chan struct{}),
	}, nil
}

// Stop signals all goroutines to exit.
func (s *PeerServer) Stop() {
	close(s.quit)
}

// ---------------------------------------------------------------------------
// Listening
// ---------------------------------------------------------------------------

// ListenAndServe binds the TCP listener and accepts inbound connections.
// Blocks until Stop() is called.
func (s *PeerServer) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("p2p: listen %s: %w", s.listenAddr, err)
	}
	defer ln.Close()
	log.Printf("[p2p] listening on %s (engine: %s)", s.listenAddr, s.engine.Name())

	// Unblock Accept() when Stop() fires.
	go func() {
		<-s.quit
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return nil
			default:
				log.Printf("[p2p] accept error: %v", err)
				continue
			}
		}
		go s.handleInbound(conn)
	}
}

// handleInbound runs the acceptor (Node B) side of the handshake and then
// starts the peer read loop.
func (s *PeerServer) handleInbound(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	log.Printf("[p2p] inbound connection from %s", remote)

	start := time.Now()

	// --- Handshake Step 2: receive MsgHandshakeInit ---
	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	pkt, err := readPacket(conn)
	if err != nil {
		log.Printf("[p2p] handshake read from %s: %v", remote, err)
		conn.Close()
		return
	}
	if pkt.Type != MsgHandshakeInit {
		log.Printf("[p2p] unexpected packet type %d from %s (want HandshakeInit)", pkt.Type, remote)
		conn.Close()
		return
	}

	var initPayload HandshakeInitPayload
	if err := json.Unmarshal(pkt.Payload, &initPayload); err != nil {
		log.Printf("[p2p] decode HandshakeInit from %s: %v", remote, err)
		conn.Close()
		return
	}

	// Encapsulate: derive shared secret + ciphertext using peer's KEM public key.
	ciphertext, rawSecret, err := s.engine.Encapsulate(initPayload.KEMPublicKey)
	if err != nil {
		log.Printf("[p2p] Encapsulate for %s: %v", remote, err)
		conn.Close()
		return
	}

	replyPayload, err := json.Marshal(HandshakeReplyPayload{Ciphertext: ciphertext})
	if err != nil {
		log.Printf("[p2p] marshal HandshakeReply for %s: %v", remote, err)
		conn.Close()
		return
	}

	if err := writePacket(conn, Packet{Type: MsgHandshakeReply, Payload: replyPayload}); err != nil {
		log.Printf("[p2p] write HandshakeReply to %s: %v", remote, err)
		conn.Close()
		return
	}

	elapsed := time.Since(start)
	sessionKey := deriveSessionKey(rawSecret)

	log.Printf("[p2p] handshake complete with %s (acceptor) in %v | session key prefix: %x",
		remote, elapsed, sessionKey[:4])

	// Clear the deadline; per-message I/O will set its own.
	conn.SetDeadline(time.Time{})

	peer := s.registerPeer(remote, conn, sessionKey)
	s.runPeer(peer)
}

// ---------------------------------------------------------------------------
// Outbound dialling
// ---------------------------------------------------------------------------

// ConnectToPeers dials each address in addrs and starts a reconnect loop for
// each one. Safe to call from a goroutine; returns immediately.
func (s *PeerServer) ConnectToPeers(addrs []string) {
	for _, addr := range addrs {
		go s.reconnectLoop(addr)
	}
}

// reconnectLoop maintains a persistent connection to addr, reconnecting with
// exponential backoff whenever the link drops.
func (s *PeerServer) reconnectLoop(addr string) {
	backoff := reconnectBase
	for {
		select {
		case <-s.quit:
			return
		default:
		}

		if err := s.dialPeer(addr); err != nil {
			log.Printf("[p2p] connection to %s failed: %v — retrying in %v", addr, err, backoff)
			select {
			case <-time.After(backoff):
			case <-s.quit:
				return
			}
			backoff *= 2
			if backoff > reconnectCap {
				backoff = reconnectCap
			}
			continue
		}
		// Successful connection. Reset backoff.
		backoff = reconnectBase
	}
}

// dialPeer opens a TCP connection to addr, runs the initiator (Node A) side
// of the KEM handshake, then hands the connection off to runPeer.
func (s *PeerServer) dialPeer(addr string) error {
	// Tie-break: the lexicographically smaller listenAddr is always the initiator.
	// If our address is larger we would normally be the acceptor, but since we are
	// dialling here we always send HandshakeInit regardless — the remote side
	// checks the tie-break when it receives our connection to decide whether to
	// expect or send the init message.
	//
	// For the 3-node Docker setup the addresses are fixed and distinct, so
	// the side with the lower address always dials first and wins the tie-break.
	// We enforce it explicitly: if our listenAddr >= addr we are the acceptor for
	// this pair and must NOT dial (the remote will dial us). Skip.
	if s.listenAddr >= addr {
		// We expect this peer to dial us; handleInbound will pick it up.
		return nil
	}

	conn, err := net.DialTimeout("tcp", addr, handshakeTimeout)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	start := time.Now()
	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	// --- Handshake Step 1: send MsgHandshakeInit ---
	initPayload, err := json.Marshal(HandshakeInitPayload{KEMPublicKey: s.kemPubKey})
	if err != nil {
		conn.Close()
		return fmt.Errorf("marshal HandshakeInit: %w", err)
	}
	if err := writePacket(conn, Packet{Type: MsgHandshakeInit, Payload: initPayload}); err != nil {
		conn.Close()
		return fmt.Errorf("write HandshakeInit: %w", err)
	}

	// --- Handshake Step 3: receive MsgHandshakeReply ---
	pkt, err := readPacket(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("read HandshakeReply: %w", err)
	}
	if pkt.Type != MsgHandshakeReply {
		conn.Close()
		return fmt.Errorf("unexpected packet type %d (want HandshakeReply)", pkt.Type)
	}

	var replyPayload HandshakeReplyPayload
	if err := json.Unmarshal(pkt.Payload, &replyPayload); err != nil {
		conn.Close()
		return fmt.Errorf("decode HandshakeReply: %w", err)
	}

	// Decapsulate: recover the shared secret using our KEM private key.
	rawSecret, err := s.engine.Decapsulate(replyPayload.Ciphertext, s.kemPrivKey)
	if err != nil {
		conn.Close()
		return fmt.Errorf("Decapsulate: %w", err)
	}

	elapsed := time.Since(start)
	sessionKey := deriveSessionKey(rawSecret)

	log.Printf("[p2p] handshake complete with %s (initiator) in %v | session key prefix: %x",
		addr, elapsed, sessionKey[:4])

	conn.SetDeadline(time.Time{})

	peer := s.registerPeer(addr, conn, sessionKey)
	s.runPeer(peer)
	return nil
}

// ---------------------------------------------------------------------------
// Peer lifecycle
// ---------------------------------------------------------------------------

// registerPeer stores the peer and starts its writer goroutine.
func (s *PeerServer) registerPeer(addr string, conn net.Conn, sessionKey []byte) *Peer {
	peer := &Peer{
		addr:          addr,
		conn:          conn,
		sessionKey:    sessionKey,
		send:          make(chan Packet, sendQueueDepth),
		handshakeDone: true,
	}

	s.peersMu.Lock()
	s.peers[addr] = peer
	s.peersMu.Unlock()

	go s.writerLoop(peer)
	return peer
}

// removePeer cleans up a disconnected peer.
func (s *PeerServer) removePeer(addr string) {
	s.peersMu.Lock()
	delete(s.peers, addr)
	s.peersMu.Unlock()
}

// runPeer is the inbound read loop for an established peer connection.
// Blocks until the connection closes or Stop() is called.
func (s *PeerServer) runPeer(peer *Peer) {
	defer func() {
		peer.conn.Close()
		s.removePeer(peer.addr)
		log.Printf("[p2p] peer %s disconnected", peer.addr)
	}()

	for {
		select {
		case <-s.quit:
			return
		default:
		}

		peer.conn.SetDeadline(time.Now().Add(ioTimeout))
		pkt, err := readPacket(peer.conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("[p2p] read from %s: %v", peer.addr, err)
			}
			return
		}

		if err := s.handlePacket(peer, pkt); err != nil {
			log.Printf("[p2p] handle packet from %s: %v", peer.addr, err)
		}
	}
}

// writerLoop drains peer.send and writes packets to the wire.
func (s *PeerServer) writerLoop(peer *Peer) {
	for {
		select {
		case <-s.quit:
			return
		case pkt, ok := <-peer.send:
			if !ok {
				return
			}
			peer.conn.SetDeadline(time.Now().Add(ioTimeout))
			if err := writePacket(peer.conn, pkt); err != nil {
				log.Printf("[p2p] write to %s: %v", peer.addr, err)
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Packet dispatch
// ---------------------------------------------------------------------------

// handlePacket routes an inbound packet to the appropriate handler.
func (s *PeerServer) handlePacket(origin *Peer, pkt Packet) error {
	switch pkt.Type {
	case MsgTransaction:
		return s.handleTransaction(origin, pkt.Payload)
	case MsgBlock:
		return s.handleBlock(origin, pkt.Payload)
	default:
		return fmt.Errorf("unknown message type %d", pkt.Type)
	}
}

// handleTransaction validates an inbound transaction and floods it to all
// other peers.
func (s *PeerServer) handleTransaction(origin *Peer, payload []byte) error {
	var tp TransactionPayload
	if err := json.Unmarshal(payload, &tp); err != nil {
		return fmt.Errorf("decode transaction: %w", err)
	}

	if err := s.ledger.ValidateTransaction(tp.Tx); err != nil {
		return fmt.Errorf("invalid transaction: %w", err)
	}

	// Deliver to the application layer (non-blocking drop if full).
	select {
	case s.InboundTx <- tp.Tx:
	default:
	}

	s.flood(origin, Packet{Type: MsgTransaction, Payload: payload})
	return nil
}

// handleBlock validates an inbound block and floods it to all other peers.
func (s *PeerServer) handleBlock(origin *Peer, payload []byte) error {
	var bp BlockPayload
	if err := json.Unmarshal(payload, &bp); err != nil {
		return fmt.Errorf("decode block: %w", err)
	}

	if err := s.ledger.AddBlock(bp.Block); err != nil {
		return fmt.Errorf("invalid block: %w", err)
	}

	select {
	case s.InboundBlock <- bp.Block:
	default:
	}

	s.flood(origin, Packet{Type: MsgBlock, Payload: payload})
	return nil
}

// ---------------------------------------------------------------------------
// Broadcast helpers
// ---------------------------------------------------------------------------

// BroadcastTransaction encodes a transaction and enqueues it to all peers.
// Called by the node's own block-producer loop when it creates a transaction.
func (s *PeerServer) BroadcastTransaction(tx consensus.Transaction) error {
	payload, err := json.Marshal(TransactionPayload{Tx: tx})
	if err != nil {
		return err
	}
	s.flood(nil, Packet{Type: MsgTransaction, Payload: payload})
	return nil
}

// BroadcastBlock encodes a block and enqueues it to all peers.
func (s *PeerServer) BroadcastBlock(block consensus.Block) error {
	payload, err := json.Marshal(BlockPayload{Block: block})
	if err != nil {
		return err
	}
	s.flood(nil, Packet{Type: MsgBlock, Payload: payload})
	return nil
}

// flood enqueues pkt to every peer except origin.
// If a peer's send queue is full the packet is dropped for that peer only.
func (s *PeerServer) flood(origin *Peer, pkt Packet) {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	for _, p := range s.peers {
		if origin != nil && p.addr == origin.addr {
			continue
		}
		select {
		case p.send <- pkt:
		default:
			log.Printf("[p2p] send queue full for peer %s — dropping packet", p.addr)
		}
	}
}

// ---------------------------------------------------------------------------
// Wire framing helpers
// ---------------------------------------------------------------------------

// writePacket serialises pkt as [4-byte length][1-byte type][payload] and
// writes it atomically to w.
func writePacket(w io.Writer, pkt Packet) error {
	// Frame layout: 4-byte total length (type byte + payload), then body.
	body := make([]byte, 1+len(pkt.Payload))
	body[0] = byte(pkt.Type)
	copy(body[1:], pkt.Payload)

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))

	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// readPacket reads a single length-prefixed packet from r.
func readPacket(r io.Reader) (Packet, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return Packet{}, err
	}
	length := binary.BigEndian.Uint32(header)

	if length == 0 {
		return Packet{}, fmt.Errorf("p2p: received zero-length packet")
	}
	// Guard against obviously malformed packets (max 10 MB).
	const maxPacketSize = 10 << 20
	if length > maxPacketSize {
		return Packet{}, fmt.Errorf("p2p: packet length %d exceeds maximum", length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return Packet{}, err
	}

	return Packet{
		Type:    MessageType(body[0]),
		Payload: body[1:],
	}, nil
}

// ---------------------------------------------------------------------------
// Cryptographic helpers
// ---------------------------------------------------------------------------

// deriveSessionKey returns SHA-256(rawSharedSecret).
// The raw secret is discarded after derivation; only the 32-byte derived key
// is stored in Peer.sessionKey for metrics logging.
func deriveSessionKey(rawSharedSecret []byte) []byte {
	h := sha256.Sum256(rawSharedSecret)
	return h[:]
}
