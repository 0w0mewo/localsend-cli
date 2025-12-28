package signaling

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	// DefaultSignalingServer is the public LocalSend signaling server.
	DefaultSignalingServer = "wss://public.localsend.org/v1/ws"

	// Ping interval to keep connection alive.
	pingInterval = 2 * time.Minute

	// Write timeout for WebSocket messages.
	writeTimeout = 10 * time.Second
)

// SignalingClient manages connection to the LocalSend signaling server.
type SignalingClient struct {
	conn     *websocket.Conn
	client   ClientInfo             // Our info with server-assigned ID
	peers    map[uuid.UUID]ClientInfo
	peersMu  sync.RWMutex
	msgChan  chan WsServerMessage
	sendChan chan WsClientMessage
	done     chan struct{}
	onAnswer map[string]func(WsServerMessage) // sessionID -> callback
	answerMu sync.Mutex
}

// Connect establishes a WebSocket connection to the signaling server.
func Connect(uri string, info ClientInfoWithoutID) (*SignalingClient, error) {
	// Encode client info as base64 JSON in query parameter
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client info: %w", err)
	}
	encodedInfo := base64.RawStdEncoding.EncodeToString(infoJSON)

	// Build WebSocket URL with query parameter
	wsURL, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid signaling server URL: %w", err)
	}
	q := wsURL.Query()
	q.Set("d", encodedInfo)
	wsURL.RawQuery = q.Encode()

	slog.Debug("Connecting to signaling server", "url", wsURL.String())

	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to signaling server: %w", err)
	}

	client := &SignalingClient{
		conn:     conn,
		peers:    make(map[uuid.UUID]ClientInfo),
		msgChan:  make(chan WsServerMessage, 16),
		sendChan: make(chan WsClientMessage, 16),
		done:     make(chan struct{}),
		onAnswer: make(map[string]func(WsServerMessage)),
	}

	// Wait for HELLO message
	if err := client.waitForHello(); err != nil {
		conn.Close()
		return nil, err
	}

	// Start background goroutines
	go client.readLoop()
	go client.writeLoop()
	go client.pingLoop()

	slog.Info("Connected to signaling server", "id", client.client.ID, "peers", len(client.peers))

	return client, nil
}

// waitForHello waits for the initial HELLO message from the server.
func (c *SignalingClient) waitForHello() error {
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	_, msgBytes, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read HELLO: %w", err)
	}

	var msg WsServerMessage
	if err := json.Unmarshal(msgBytes, &msg); err != nil {
		return fmt.Errorf("failed to parse HELLO: %w", err)
	}

	if msg.Type != "HELLO" {
		return fmt.Errorf("expected HELLO, got %s", msg.Type)
	}

	if msg.Client == nil {
		return fmt.Errorf("HELLO missing client info")
	}

	c.client = *msg.Client
	for _, peer := range msg.Peers {
		c.peers[peer.ID] = peer
	}

	return nil
}

// readLoop reads messages from the WebSocket.
func (c *SignalingClient) readLoop() {
	defer close(c.msgChan)

	for {
		_, msgBytes, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				slog.Warn("WebSocket read error", "error", err)
			}
			return
		}

		var msg WsServerMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			slog.Warn("Failed to parse message", "error", err, "msg", string(msgBytes))
			continue
		}

		// Handle peer updates
		c.handlePeerUpdate(msg)

		// Handle answer callbacks
		if msg.Type == "ANSWER" && msg.SessionID != "" {
			c.answerMu.Lock()
			if callback, ok := c.onAnswer[msg.SessionID]; ok {
				delete(c.onAnswer, msg.SessionID)
				c.answerMu.Unlock()
				callback(msg)
				continue
			}
			c.answerMu.Unlock()
		}

		// Forward to message channel
		select {
		case c.msgChan <- msg:
		case <-c.done:
			return
		}
	}
}

// writeLoop sends messages to the WebSocket.
func (c *SignalingClient) writeLoop() {
	for {
		select {
		case msg := <-c.sendChan:
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := c.conn.WriteJSON(msg); err != nil {
				slog.Warn("Failed to send message", "error", err)
			}
		case <-c.done:
			return
		}
	}
}

// pingLoop sends periodic pings to keep the connection alive.
func (c *SignalingClient) pingLoop() {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				slog.Warn("Failed to send ping", "error", err)
				return
			}
		case <-c.done:
			return
		}
	}
}

// handlePeerUpdate updates the peer list based on server messages.
func (c *SignalingClient) handlePeerUpdate(msg WsServerMessage) {
	c.peersMu.Lock()
	defer c.peersMu.Unlock()

	switch msg.Type {
	case "JOIN":
		if msg.Peer != nil {
			c.peers[msg.Peer.ID] = *msg.Peer
			slog.Info("Peer joined", "alias", msg.Peer.Alias, "id", msg.Peer.ID)
		}
	case "UPDATE":
		if msg.Peer != nil {
			c.peers[msg.Peer.ID] = *msg.Peer
		}
	case "LEFT":
		if msg.PeerID != nil {
			if peer, ok := c.peers[*msg.PeerID]; ok {
				slog.Info("Peer left", "alias", peer.Alias, "id", *msg.PeerID)
			}
			delete(c.peers, *msg.PeerID)
		}
	}
}

// Close closes the signaling connection.
func (c *SignalingClient) Close() error {
	close(c.done)
	return c.conn.Close()
}

// ClientID returns our client ID assigned by the server.
func (c *SignalingClient) ClientID() uuid.UUID {
	return c.client.ID
}

// ClientInfo returns our client info.
func (c *SignalingClient) ClientInfo() ClientInfo {
	return c.client
}

// GetPeers returns a copy of all known peers.
func (c *SignalingClient) GetPeers() []ClientInfo {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()

	peers := make([]ClientInfo, 0, len(c.peers))
	for _, peer := range c.peers {
		peers = append(peers, peer)
	}
	return peers
}

// GetPeer returns a specific peer by ID.
func (c *SignalingClient) GetPeer(id uuid.UUID) (ClientInfo, bool) {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()
	peer, ok := c.peers[id]
	return peer, ok
}

// Messages returns a channel for receiving server messages.
func (c *SignalingClient) Messages() <-chan WsServerMessage {
	return c.msgChan
}

// SendUpdate sends an UPDATE message to the server.
func (c *SignalingClient) SendUpdate(info ClientInfoWithoutID) error {
	msg := NewUpdateMessage(info)
	select {
	case c.sendChan <- msg:
		return nil
	case <-c.done:
		return fmt.Errorf("connection closed")
	}
}

// SendOffer sends an OFFER message to a target peer.
func (c *SignalingClient) SendOffer(sessionID string, target uuid.UUID, sdp string) error {
	compressedSDP, err := CompressSDP(sdp)
	if err != nil {
		return fmt.Errorf("failed to compress SDP: %w", err)
	}

	msg := NewOfferMessage(sessionID, target, compressedSDP)
	select {
	case c.sendChan <- msg:
		return nil
	case <-c.done:
		return fmt.Errorf("connection closed")
	}
}

// SendAnswer sends an ANSWER message to a target peer.
func (c *SignalingClient) SendAnswer(sessionID string, target uuid.UUID, sdp string) error {
	compressedSDP, err := CompressSDP(sdp)
	if err != nil {
		return fmt.Errorf("failed to compress SDP: %w", err)
	}

	msg := NewAnswerMessage(sessionID, target, compressedSDP)
	select {
	case c.sendChan <- msg:
		return nil
	case <-c.done:
		return fmt.Errorf("connection closed")
	}
}

// OnAnswer registers a callback for when an ANSWER is received for a session.
func (c *SignalingClient) OnAnswer(sessionID string, callback func(WsServerMessage)) {
	c.answerMu.Lock()
	defer c.answerMu.Unlock()
	c.onAnswer[sessionID] = callback
}
