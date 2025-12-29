package transfer

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/crypto"
	"github.com/0w0mewo/localsend-cli/internal/webrtc/signaling"
)

// Receiver handshake states
const (
	stateWaitNonce = iota
	stateWaitToken
	stateWaitPin
	stateWaitFileList
	stateWaitFiles
	stateReceivingFiles
)

// RTCReceiver handles receiving files over WebRTC.
type RTCReceiver struct {
	signaling  *signaling.SignalingClient
	signingKey *crypto.SigningKey
	peer       *PeerConnection
	pin        string
	pinAttempts int
	saveDir    string
	mu         sync.Mutex

	// Handshake state
	state       int
	remoteNonce []byte
	localNonce  []byte
	finalNonce  []byte

	// Files
	files       []RTCFileDto
	fileTokens  map[string]string // fileId -> token
	acceptedIDs []string

	// File writers
	currentFileID string
	fileWriters   map[string]*os.File

	// Callbacks
	onSelectFiles func([]RTCFileDto) []string
}

// NewRTCReceiver creates a new WebRTC receiver.
func NewRTCReceiver(sig *signaling.SignalingClient, key *crypto.SigningKey, pin, saveDir string) *RTCReceiver {
	return &RTCReceiver{
		signaling:   sig,
		signingKey:  key,
		pin:         pin,
		saveDir:     saveDir,
		state:       stateWaitNonce,
		fileTokens:  make(map[string]string),
		fileWriters: make(map[string]*os.File),
	}
}

// OnSelectFiles sets the callback for selecting which files to accept.
func (r *RTCReceiver) OnSelectFiles(handler func([]RTCFileDto) []string) {
	r.onSelectFiles = handler
}

// AcceptOffer accepts an incoming WebRTC offer.
func (r *RTCReceiver) AcceptOffer(offer signaling.WsServerMessage) error {
	if offer.Peer == nil {
		return fmt.Errorf("offer missing peer info")
	}

	sdp, err := signaling.DecompressSDP(offer.SDP)
	if err != nil {
		return fmt.Errorf("failed to decompress SDP: %w", err)
	}

	peer, err := NewPeerConnection(PeerConfig{
		STUNServers: DefaultSTUNServers,
		IsInitiator: false,
	})
	if err != nil {
		return fmt.Errorf("failed to create peer connection: %w", err)
	}
	r.peer = peer
	r.state = stateWaitNonce

	peer.OnMessage(r.handleMessage)

	answer, err := peer.AcceptOffer(sdp)
	if err != nil {
		peer.Close()
		return fmt.Errorf("failed to accept offer: %w", err)
	}

	if err := r.signaling.SendAnswer(offer.SessionID, offer.Peer.ID, answer); err != nil {
		peer.Close()
		return fmt.Errorf("failed to send answer: %w", err)
	}

	slog.Info("Sent answer", "peer", offer.Peer.Alias, "session", offer.SessionID)
	return nil
}

// handleMessage processes incoming data channel messages.
func (r *RTCReceiver) handleMessage(data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	slog.Debug("Message received", "state", r.state, "len", len(data))

	// Check for delimiter (string message with len <= 1, like "0")
	if len(data) <= 1 {
		slog.Debug("Delimiter received, skipping")
		return
	}

	// If we're receiving file binary data (non-JSON)
	if r.state == stateReceivingFiles && r.currentFileID != "" {
		// Check if this is a new file header (JSON) or binary data
		if data[0] == '{' {
			// This might be a file header for next file
			var header RTCSendFileHeader
			if err := json.Unmarshal(data, &header); err == nil && header.ID != "" {
				slog.Info("Received file header", "id", header.ID)
				r.currentFileID = header.ID
				return
			}
		}
		r.handleBinaryData(data)
		return
	}

	// Parse message type
	msg, msgType, err := ParseRTCMessage(data)
	if err != nil || msg == nil {
		// Could be binary data in wrong state, or malformed JSON
		if r.state == stateWaitFiles && data[0] != '{' {
			// Binary data without header - might be continuation
			slog.Debug("Possible binary data, treating as file content")
			r.handleBinaryData(data)
			return
		}
		slog.Warn("Failed to parse RTC message", "error", err)
		return
	}

	slog.Debug("Parsed RTC message", "type", msgType)

	switch r.state {
	case stateWaitNonce:
		r.handleNonce(msg, msgType)
	case stateWaitToken:
		r.handleToken(msg, msgType)
	case stateWaitPin:
		r.handlePin(msg, msgType)
	case stateWaitFileList:
		r.handleFileList(msg, msgType, data)
	case stateWaitFiles:
		r.handleFileHeader(msg, msgType)
	}
}

// handleNonce processes the nonce message from sender.
func (r *RTCReceiver) handleNonce(msg interface{}, msgType string) {
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
	r.remoteNonce = remoteNonce

	// Generate and send our nonce
	localNonce, err := crypto.GenerateNonce()
	if err != nil {
		slog.Error("Failed to generate nonce", "error", err)
		return
	}
	r.localNonce = localNonce

	// Final nonce = sender_nonce || receiver_nonce
	r.finalNonce = append(r.remoteNonce, r.localNonce...)

	response := RTCNonceMessage{
		Nonce: crypto.EncodeNonce(localNonce),
	}
	if err := r.sendJSON(response); err != nil {
		slog.Error("Failed to send nonce response", "error", err)
		return
	}

	slog.Info("Nonce exchange complete")
	r.state = stateWaitToken
}

// handleToken processes the token message from sender.
func (r *RTCReceiver) handleToken(msg interface{}, msgType string) {
	if msgType != "token_request" {
		slog.Warn("Expected token_request, got", "type", msgType)
		return
	}

	tokenReq := msg.(*RTCTokenRequest)
	tokenPreview := tokenReq.Token
	if len(tokenPreview) > 30 {
		tokenPreview = tokenPreview[:30] + "..."
	}
	slog.Info("Received token from sender", "token", tokenPreview)

	// Generate our token
	token, err := r.signingKey.GenerateTokenWithNonce(r.finalNonce)
	if err != nil {
		slog.Error("Failed to generate token", "error", err)
		return
	}

	// Send token response (with or without PIN requirement)
	var response RTCTokenResponse
	if r.pin != "" {
		response = RTCTokenResponse{Status: "PIN_REQUIRED", Token: token}
	} else {
		response = RTCTokenResponse{Status: "OK", Token: token}
	}

	if err := r.sendJSON(response); err != nil {
		slog.Error("Failed to send token response", "error", err)
		return
	}

	slog.Info("Token exchange complete", "status", response.Status)
	if response.Status == "PIN_REQUIRED" {
		r.state = stateWaitPin
	} else {
		r.state = stateWaitFileList
	}
}

// handlePin processes the PIN message from sender.
func (r *RTCReceiver) handlePin(msg interface{}, msgType string) {
	if msgType != "pin" {
		slog.Warn("Expected pin, got", "type", msgType)
		return
	}

	pinMsg := msg.(*RTCPinMessage)
	slog.Info("Received PIN challenge")

	if pinMsg.Pin == r.pin {
		slog.Info("PIN correct")
		response := RTCPinReceivingResponse{Status: "OK"}
		r.sendJSON(response)
		r.state = stateWaitFileList
		return
	}

	r.pinAttempts++
	slog.Warn("Incorrect PIN", "attempt", r.pinAttempts)

	if r.pinAttempts >= 3 {
		slog.Error("Too many PIN attempts, closing connection")
		response := RTCPinReceivingResponse{Status: "TOO_MANY_ATTEMPTS"}
		r.sendJSON(response)
		r.Close()
		return
	}

	response := RTCPinReceivingResponse{Status: "PIN_REQUIRED"}
	r.sendJSON(response)
}

// handleFileList processes the file list from sender.
func (r *RTCReceiver) handleFileList(_ interface{}, msgType string, data []byte) {
	// File list comes as RTCPinSendingResponse with status OK
	if msgType != "file_list" && msgType != "status_OK" {
		slog.Warn("Expected file_list, got", "type", msgType)
		return
	}

	// Parse as RTCPinSendingResponse
	var fileListMsg RTCPinSendingResponse
	if err := json.Unmarshal(data, &fileListMsg); err != nil {
		slog.Error("Failed to parse file list", "error", err)
		return
	}

	r.files = fileListMsg.Files
	slog.Info("Received file list", "count", len(r.files))

	for _, f := range r.files {
		slog.Info("File", "name", f.FileName, "size", f.Size)
	}

	// Select files to accept
	var acceptedIDs []string
	if r.onSelectFiles != nil {
		acceptedIDs = r.onSelectFiles(r.files)
	} else {
		// Accept all by default
		for _, f := range r.files {
			acceptedIDs = append(acceptedIDs, f.ID)
		}
	}
	r.acceptedIDs = acceptedIDs

	if len(acceptedIDs) == 0 {
		response := RTCFileListResponse{Status: "DECLINED"}
		r.sendJSON(response)
		slog.Info("Declined all files")
		return
	}

	// Generate simple UUID tokens for each accepted file (matches official implementation)
	fileTokens := make(map[string]string)
	for _, id := range acceptedIDs {
		token := fmt.Sprintf("%d", time.Now().UnixNano()) // Simple unique token
		fileTokens[id] = token
		r.fileTokens[id] = token

		// Create file writer
		for _, f := range r.files {
			if f.ID == id {
				path := filepath.Join(r.saveDir, f.FileName)
				file, err := os.Create(path)
				if err != nil {
					slog.Error("Failed to create file", "path", path, "error", err)
					continue
				}
				r.fileWriters[id] = file
				slog.Info("Ready to receive", "file", f.FileName)
				break
			}
		}
	}

	// Send acceptance with file tokens as binary (official protocol uses chunked binary)
	response := RTCFileListResponse{
		Status: "OK",
		Files:  fileTokens,
	}
	if err := r.sendJSONBinary(response); err != nil {
		slog.Error("Failed to send file acceptance", "error", err)
		return
	}

	// Send delimiter to signal end of our response (required by protocol)
	if err := r.sendDelimiter(); err != nil {
		slog.Error("Failed to send delimiter", "error", err)
		return
	}

	slog.Info("Sent file acceptance and delimiter", "count", len(fileTokens))
	r.state = stateWaitFiles
}

// handleFileHeader processes file header before binary data.
func (r *RTCReceiver) handleFileHeader(msg interface{}, msgType string) {
	if msgType != "file_header" {
		slog.Debug("Non-file-header in file receive state", "type", msgType)
		return
	}

	header := msg.(*RTCSendFileHeader)
	slog.Info("Receiving file", "id", header.ID)
	r.currentFileID = header.ID
	r.state = stateReceivingFiles
}

// handleBinaryData writes received file data.
func (r *RTCReceiver) handleBinaryData(data []byte) {
	if f, ok := r.fileWriters[r.currentFileID]; ok {
		n, err := f.Write(data)
		if err != nil {
			slog.Error("Failed to write data", "error", err)
		} else {
			slog.Info("Wrote file data", "fileId", r.currentFileID, "bytes", n)
			f.Sync() // Ensure data is flushed to disk
		}
	} else {
		slog.Warn("No file writer for current file", "fileId", r.currentFileID)
	}
}

// sendJSON sends a JSON message through the data channel as text (for simple responses).
func (r *RTCReceiver) sendJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	slog.Info("Sending message", "content", string(data))
	return r.peer.SendText(string(data))
}

// sendJSONBinary sends JSON as binary data (for chunked protocol responses).
func (r *RTCReceiver) sendJSONBinary(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	slog.Info("Sending binary message", "content", string(data))
	return r.peer.Send(data)
}

// sendDelimiter sends the delimiter to signal end of chunked message.
func (r *RTCReceiver) sendDelimiter() error {
	return r.peer.SendText("0")
}

// Close closes the receiver.
func (r *RTCReceiver) Close() error {
	for _, f := range r.fileWriters {
		f.Close()
	}
	if r.peer != nil {
		return r.peer.Close()
	}
	return nil
}

// ListenForOffers listens for incoming WebRTC offers.
func (r *RTCReceiver) ListenForOffers(onOffer func(offer signaling.WsServerMessage)) {
	go func() {
		for msg := range r.signaling.Messages() {
			if msg.Type == "OFFER" {
				onOffer(msg)
			}
		}
	}()
}
