package transfer

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/crypto"
	"github.com/0w0mewo/localsend-cli/internal/webrtc/signaling"
	"github.com/google/uuid"
)

const (
	// ChunkSize is the size of each binary chunk sent over WebRTC.
	ChunkSize = 16 * 1024 // 16KB chunks
)

// Sender handshake states
const (
	senderStateInit = iota
	senderStateWaitNonce
	senderStateWaitToken
	senderStateWaitFileAccept
	senderStateSendingFiles
	senderStateDone
)

// FileMeta represents file metadata for sending.
type FileMeta struct {
	ID       string
	FileName string
	FilePath string
	Size     int64
	FileType string
	Modified time.Time
}

// RTCSender handles sending files over WebRTC using official protocol.
type RTCSender struct {
	signaling  *signaling.SignalingClient
	signingKey *crypto.SigningKey
	peer       *PeerConnection
	pin        string
	sessionID  string
	mu         sync.Mutex

	// State machine
	state       int
	localNonce  []byte
	remoteNonce []byte
	finalNonce  []byte

	// Files
	files       []FileMeta
	fileTokens  map[string]string // fileId -> token from receiver
	acceptedIDs []string

	// Channels
	ready     chan struct{}
	accepted  chan map[string]string // fileId -> token
	declined  chan struct{}
	errors    chan error
}

// NewRTCSender creates a new WebRTC sender.
func NewRTCSender(sig *signaling.SignalingClient, key *crypto.SigningKey, pin string) *RTCSender {
	return &RTCSender{
		signaling:  sig,
		signingKey: key,
		pin:        pin,
		sessionID:  uuid.New().String()[:11], // Short session ID like official
		state:      senderStateInit,
		fileTokens: make(map[string]string),
		ready:      make(chan struct{}),
		accepted:   make(chan map[string]string, 1),
		declined:   make(chan struct{}, 1),
		errors:     make(chan error, 1),
	}
}

// Send initiates a file transfer to the target peer.
func (s *RTCSender) Send(target uuid.UUID, files []FileMeta) error {
	s.files = files

	// Create peer connection as initiator
	peer, err := NewPeerConnection(PeerConfig{
		STUNServers: DefaultSTUNServers,
		IsInitiator: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create peer connection: %w", err)
	}
	s.peer = peer

	// Set up message handler
	peer.OnMessage(s.handleMessage)
	peer.OnOpen(func() {
		slog.Info("Data channel opened, starting nonce exchange")
		s.startNonceExchange()
	})

	// Create offer
	sdp, err := peer.CreateOffer()
	if err != nil {
		peer.Close()
		return fmt.Errorf("failed to create offer: %w", err)
	}

	// Set up answer handler
	answerChan := make(chan string, 1)
	s.signaling.OnAnswer(s.sessionID, func(msg signaling.WsServerMessage) {
		answer, err := signaling.DecompressSDP(msg.SDP)
		if err != nil {
			slog.Error("Failed to decompress SDP answer", "error", err)
			return
		}
		answerChan <- answer
	})

	// Send offer via signaling
	if err := s.signaling.SendOffer(s.sessionID, target, sdp); err != nil {
		peer.Close()
		return fmt.Errorf("failed to send offer: %w", err)
	}

	slog.Info("Sent offer, waiting for answer", "target", target, "session", s.sessionID)

	// Wait for answer with timeout
	select {
	case answer := <-answerChan:
		if err := peer.SetAnswer(answer); err != nil {
			peer.Close()
			return fmt.Errorf("failed to set answer: %w", err)
		}
		slog.Info("Received answer, waiting for connection")
	case <-time.After(30 * time.Second):
		peer.Close()
		return fmt.Errorf("timeout waiting for answer")
	}

	// Wait for file acceptance
	select {
	case tokens := <-s.accepted:
		s.fileTokens = tokens
		for id := range tokens {
			s.acceptedIDs = append(s.acceptedIDs, id)
		}
		slog.Info("Files accepted", "count", len(tokens))
	case <-s.declined:
		peer.Close()
		return fmt.Errorf("transfer declined by receiver")
	case err := <-s.errors:
		peer.Close()
		return err
	case <-time.After(60 * time.Second):
		peer.Close()
		return fmt.Errorf("timeout waiting for file acceptance")
	}

	return nil
}

// startNonceExchange begins the official protocol handshake.
func (s *RTCSender) startNonceExchange() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate our nonce
	nonce, err := crypto.GenerateNonce()
	if err != nil {
		s.errors <- fmt.Errorf("failed to generate nonce: %w", err)
		return
	}
	s.localNonce = nonce

	// Send nonce
	msg := RTCNonceMessage{Nonce: crypto.EncodeNonce(nonce)}
	if err := s.sendJSON(msg); err != nil {
		s.errors <- fmt.Errorf("failed to send nonce: %w", err)
		return
	}

	slog.Info("Sent nonce, waiting for receiver's nonce")
	s.state = senderStateWaitNonce
}

// handleMessage processes incoming data channel messages.
func (s *RTCSender) handleMessage(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	slog.Debug("Message received", "state", s.state, "len", len(data))

	// Check for delimiter
	if len(data) <= 1 {
		slog.Debug("Delimiter received")
		return
	}

	// Parse message
	msg, msgType, err := ParseRTCMessage(data)
	if err != nil || msg == nil {
		slog.Warn("Failed to parse RTC message", "error", err)
		return
	}

	slog.Debug("Parsed RTC message", "type", msgType)

	switch s.state {
	case senderStateWaitNonce:
		s.handleNonceResponse(msg, msgType)
	case senderStateWaitToken:
		s.handleTokenResponse(msg, msgType, data)
	case senderStateWaitFileAccept:
		s.handleFileAcceptance(msg, msgType, data)
	}
}

// handleNonceResponse processes the nonce from receiver.
func (s *RTCSender) handleNonceResponse(msg interface{}, msgType string) {
	if msgType != "nonce" {
		slog.Warn("Expected nonce, got", "type", msgType)
		return
	}

	nonceMsg := msg.(*RTCNonceMessage)
	remoteNonce, err := crypto.DecodeNonce(nonceMsg.Nonce)
	if err != nil {
		slog.Error("Failed to decode remote nonce", "error", err)
		return
	}
	s.remoteNonce = remoteNonce

	// Final nonce = sender_nonce || receiver_nonce
	s.finalNonce = append(s.localNonce, s.remoteNonce...)

	slog.Info("Nonce exchange complete, sending token")

	// Generate and send token
	token, err := s.signingKey.GenerateTokenWithNonce(s.finalNonce)
	if err != nil {
		slog.Error("Failed to generate token", "error", err)
		return
	}

	tokenMsg := RTCTokenRequest{Token: token}
	if err := s.sendJSON(tokenMsg); err != nil {
		slog.Error("Failed to send token", "error", err)
		return
	}

	s.state = senderStateWaitToken
}

// handleTokenResponse processes the token response from receiver.
func (s *RTCSender) handleTokenResponse(_ interface{}, msgType string, data []byte) {
	// Token response has status field
	if msgType != "status_OK" && msgType != "status_PIN_REQUIRED" {
		slog.Warn("Expected token response, got", "type", msgType)
		return
	}

	var tokenResp RTCTokenResponse
	if err := json.Unmarshal(data, &tokenResp); err != nil {
		slog.Error("Failed to parse token response", "error", err)
		return
	}

	slog.Info("Token response received", "status", tokenResp.Status)

	if tokenResp.Status == "PIN_REQUIRED" {
		// Handle PIN requirement
		if s.pin == "" {
			s.errors <- fmt.Errorf("receiver requires PIN but none provided")
			return
		}
		// Send PIN message
		pinMsg := RTCPinMessage{Pin: s.pin}
		if err := s.sendJSON(pinMsg); err != nil {
			s.errors <- fmt.Errorf("failed to send PIN: %w", err)
			return
		}
		slog.Info("Sent PIN, waiting for verification")
		// Stay in senderStateWaitToken to receive PIN response
		return
	}

	// Send file list
	slog.Info("Sending file list")
	s.sendFileList()
}

// sendFileList sends the list of files to transfer.
func (s *RTCSender) sendFileList() {
	files := make([]RTCFileDto, len(s.files))
	for i, f := range s.files {
		files[i] = RTCFileDto{
			ID:       f.ID,
			FileName: f.FileName,
			Size:     f.Size,
			FileType: f.FileType,
			Metadata: RTCFileMetadata{
				Modified: f.Modified.Format(time.RFC3339Nano),
			},
		}
	}

	fileList := RTCPinSendingResponse{
		Status: "OK",
		Files:  files,
	}

	// Send as binary + delimiter
	if err := s.sendJSONBinary(fileList); err != nil {
		slog.Error("Failed to send file list", "error", err)
		return
	}
	if err := s.sendDelimiter(); err != nil {
		slog.Error("Failed to send delimiter", "error", err)
		return
	}

	slog.Info("Sent file list", "count", len(files))
	s.state = senderStateWaitFileAccept
}

// handleFileAcceptance processes the file acceptance from receiver.
func (s *RTCSender) handleFileAcceptance(_ interface{}, msgType string, data []byte) {
	if msgType != "status_OK" && msgType != "status_DECLINED" {
		slog.Warn("Expected file acceptance, got", "type", msgType)
		return
	}

	var resp RTCFileListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		slog.Error("Failed to parse file acceptance", "error", err)
		return
	}

	if resp.Status == "DECLINED" {
		select {
		case s.declined <- struct{}{}:
		default:
		}
		return
	}

	// Files accepted
	select {
	case s.accepted <- resp.Files:
	default:
	}

	s.state = senderStateSendingFiles
}

// SendFiles sends all accepted files.
func (s *RTCSender) SendFiles() error {
	for _, id := range s.acceptedIDs {
		token, ok := s.fileTokens[id]
		if !ok {
			continue
		}

		// Find file
		var file *FileMeta
		for i := range s.files {
			if s.files[i].ID == id {
				file = &s.files[i]
				break
			}
		}
		if file == nil {
			continue
		}

		slog.Info("Sending file", "id", id, "name", file.FileName)

		// Open file
		f, err := os.Open(file.FilePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", file.FilePath, err)
		}

		// Send file header
		header := RTCSendFileHeader{ID: id, Token: token}
		if err := s.sendJSON(header); err != nil {
			f.Close()
			return fmt.Errorf("failed to send file header: %w", err)
		}

		// Send file data
		buf := make([]byte, ChunkSize)
		for {
			n, err := f.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return fmt.Errorf("failed to read file: %w", err)
			}

			if err := s.peer.Send(buf[:n]); err != nil {
				f.Close()
				return fmt.Errorf("failed to send data: %w", err)
			}
		}
		f.Close()

		slog.Info("File sent", "id", id, "name", file.FileName)
	}

	// Send final delimiter to signal end of all files
	if err := s.sendDelimiter(); err != nil {
		return fmt.Errorf("failed to send final delimiter: %w", err)
	}

	// Wait for buffer to actually flush instead of fixed sleep
	// This is critical per protocol spec to ensure all data is delivered
	slog.Info("Waiting for buffer to flush...")
	if err := s.peer.WaitBufferEmptyWithTimeout(10 * time.Second); err != nil {
		slog.Warn("Timeout waiting for buffer flush, continuing anyway", "error", err)
		// Don't return error - allow graceful degradation
	}

	s.state = senderStateDone
	return nil
}

// sendJSON sends a JSON message as text.
func (s *RTCSender) sendJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	slog.Debug("Sending message", "len", len(data))
	return s.peer.SendText(string(data))
}

// sendJSONBinary sends JSON as binary data.
func (s *RTCSender) sendJSONBinary(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	slog.Debug("Sending binary message", "len", len(data))
	return s.peer.Send(data)
}

// sendDelimiter sends the delimiter to signal end of chunk.
func (s *RTCSender) sendDelimiter() error {
	return s.peer.SendText("0")
}

// Close closes the sender and peer connection.
func (s *RTCSender) Close() error {
	if s.peer != nil {
		return s.peer.Close()
	}
	return nil
}
