package transfer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"
)

// Default STUN servers for ICE.
var DefaultSTUNServers = []string{
	"stun:stun.l.google.com:19302",
	"stun:stun1.l.google.com:19302",
}

// PeerConnection wraps a pion/webrtc PeerConnection for file transfer.
type PeerConnection struct {
	pc          *webrtc.PeerConnection
	dataChannel *webrtc.DataChannel
	mu          sync.Mutex
	onMessage   func([]byte)
	onOpen      func()
	onClose     func()
}

// PeerConfig configures a new peer connection.
type PeerConfig struct {
	STUNServers []string
	IsInitiator bool // true for sender (creates offer), false for receiver (creates answer)
}

// NewPeerConnection creates a new WebRTC peer connection.
func NewPeerConnection(config PeerConfig) (*PeerConnection, error) {
	stunServers := config.STUNServers
	if len(stunServers) == 0 {
		stunServers = DefaultSTUNServers
	}

	// Create ICE servers config
	iceServers := make([]webrtc.ICEServer, len(stunServers))
	for i, server := range stunServers {
		iceServers[i] = webrtc.ICEServer{URLs: []string{server}}
	}

	// Configure settings for better ICE connectivity
	settingEngine := webrtc.SettingEngine{}

	// Restrict ICE UDP ports to a known range for firewall configuration
	// This range must match the firewall rules in the KOReader plugin
	if err := settingEngine.SetEphemeralUDPPortRange(50000, 50100); err != nil {
		return nil, fmt.Errorf("failed to set UDP port range: %w", err)
	}

	// Set ICE timeouts for better reliability on slower networks
	settingEngine.SetICETimeouts(
		5*time.Second,  // disconnectedTimeout - time before marking as disconnected
		25*time.Second, // failedTimeout - time before marking as failed
		2*time.Second,  // keepAliveInterval - STUN keepalive interval
	)

	// Create API with custom settings
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	// Create peer connection with custom API
	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: iceServers,
		// Use ICE candidate pool to speed up connectivity
		ICECandidatePoolSize: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create peer connection: %w", err)
	}

	p := &PeerConnection{
		pc: pc,
	}

	// Set up connection state handler
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		slog.Info("WebRTC connection state", "state", state.String())
		if state == webrtc.PeerConnectionStateClosed ||
			state == webrtc.PeerConnectionStateFailed ||
			state == webrtc.PeerConnectionStateDisconnected {
			if p.onClose != nil {
				p.onClose()
			}
		}
		if state == webrtc.PeerConnectionStateConnected {
			slog.Info("WebRTC connection established!")
		}
	})

	// Set up ICE connection state handler for debugging
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		slog.Info("ICE connection state", "state", state.String())
		// Log additional details when checking or failed
		if state == webrtc.ICEConnectionStateChecking {
			slog.Info("ICE checking - connectivity checks in progress")
		}
		if state == webrtc.ICEConnectionStateFailed {
			slog.Error("ICE failed - no valid candidate pair found")
		}
	})

	// Set up ICE gathering state handler
	pc.OnICEGatheringStateChange(func(state webrtc.ICEGathererState) {
		slog.Info("ICE gathering state", "state", state.String())
	})

	// Set up ICE candidate handler for debugging
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate != nil {
			slog.Info("ICE candidate gathered", "type", candidate.Typ.String(), "address", candidate.Address, "port", candidate.Port, "protocol", candidate.Protocol.String())
		} else {
			slog.Info("ICE gathering complete (null candidate)")
		}
	})

	// Log when we receive any SCTP/data channel activity
	pc.SCTP().OnError(func(err error) {
		slog.Error("SCTP error", "error", err)
	})

	// If initiator, create data channel
	if config.IsInitiator {
		dc, err := pc.CreateDataChannel("data", nil)
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("failed to create data channel: %w", err)
		}
		p.setupDataChannel(dc)
	} else {
		// If receiver, wait for data channel from peer
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			slog.Info("Received data channel", "label", dc.Label())
			p.setupDataChannel(dc)
		})
	}

	return p, nil
}

// setupDataChannel configures the data channel handlers.
func (p *PeerConnection) setupDataChannel(dc *webrtc.DataChannel) {
	p.mu.Lock()
	p.dataChannel = dc
	p.mu.Unlock()

	dc.OnOpen(func() {
		slog.Info("Data channel opened", "label", dc.Label(), "id", dc.ID())
		if p.onOpen != nil {
			p.onOpen()
		}
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		slog.Debug("Data channel message received", "isString", msg.IsString, "len", len(msg.Data))
		if p.onMessage != nil {
			p.onMessage(msg.Data)
		}
	})

	dc.OnClose(func() {
		slog.Info("Data channel closed")
	})

	dc.OnError(func(err error) {
		slog.Error("Data channel error", "error", err)
	})
}

// CreateOffer creates an SDP offer.
func (p *PeerConnection) CreateOffer() (string, error) {
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create offer: %w", err)
	}

	if err := p.pc.SetLocalDescription(offer); err != nil {
		return "", fmt.Errorf("failed to set local description: %w", err)
	}

	// Wait for ICE gathering to complete
	<-webrtc.GatheringCompletePromise(p.pc)

	return p.pc.LocalDescription().SDP, nil
}

// AcceptOffer accepts an SDP offer and creates an answer.
func (p *PeerConnection) AcceptOffer(sdp string) (string, error) {
	offer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  sdp,
	}

	if err := p.pc.SetRemoteDescription(offer); err != nil {
		return "", fmt.Errorf("failed to set remote description: %w", err)
	}

	answer, err := p.pc.CreateAnswer(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create answer: %w", err)
	}

	if err := p.pc.SetLocalDescription(answer); err != nil {
		return "", fmt.Errorf("failed to set local description: %w", err)
	}

	// Wait for ICE gathering to complete
	<-webrtc.GatheringCompletePromise(p.pc)

	return p.pc.LocalDescription().SDP, nil
}

// SetAnswer sets the remote SDP answer.
func (p *PeerConnection) SetAnswer(sdp string) error {
	answer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  sdp,
	}

	if err := p.pc.SetRemoteDescription(answer); err != nil {
		return fmt.Errorf("failed to set remote description: %w", err)
	}

	return nil
}

// OnMessage sets the handler for incoming data channel messages.
func (p *PeerConnection) OnMessage(handler func([]byte)) {
	p.onMessage = handler
}

// OnOpen sets the handler for when the data channel opens.
func (p *PeerConnection) OnOpen(handler func()) {
	p.onOpen = handler
}

// OnClose sets the handler for when the connection closes.
func (p *PeerConnection) OnClose(handler func()) {
	p.onClose = handler
}

// Send sends data through the data channel.
func (p *PeerConnection) Send(data []byte) error {
	p.mu.Lock()
	dc := p.dataChannel
	p.mu.Unlock()

	if dc == nil {
		return fmt.Errorf("data channel not ready")
	}

	return dc.Send(data)
}

// SendText sends text through the data channel.
func (p *PeerConnection) SendText(text string) error {
	p.mu.Lock()
	dc := p.dataChannel
	p.mu.Unlock()

	if dc == nil {
		return fmt.Errorf("data channel not ready")
	}

	return dc.SendText(text)
}

// BufferedAmount returns the number of bytes queued in the data channel buffer.
func (p *PeerConnection) BufferedAmount() uint64 {
	p.mu.Lock()
	dc := p.dataChannel
	p.mu.Unlock()

	if dc == nil {
		return 0
	}

	return dc.BufferedAmount()
}

// WaitBufferEmpty polls until the data channel buffer is empty.
// Uses 10ms polling interval.
// Returns error if context is cancelled.
func (p *PeerConnection) WaitBufferEmpty(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if p.BufferedAmount() == 0 {
				return nil
			}
		}
	}
}

// WaitBufferEmptyWithTimeout is WaitBufferEmpty with a timeout.
func (p *PeerConnection) WaitBufferEmptyWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return p.WaitBufferEmpty(ctx)
}

// Close closes the peer connection and waits for it to fully close.
func (p *PeerConnection) Close() error {
	if p.pc == nil {
		return nil
	}

	// Close the data channel first if it exists
	p.mu.Lock()
	if p.dataChannel != nil {
		p.dataChannel.Close()
		p.dataChannel = nil
	}
	p.mu.Unlock()

	err := p.pc.Close()
	if err != nil {
		return err
	}

	// Wait for connection state to become closed (up to 2 seconds)
	for i := 0; i < 20; i++ {
		state := p.pc.ConnectionState()
		if state == webrtc.PeerConnectionStateClosed {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

// ConnectionState returns the current connection state.
func (p *PeerConnection) ConnectionState() webrtc.PeerConnectionState {
	return p.pc.ConnectionState()
}

// IsConnected returns true if the connection is established.
func (p *PeerConnection) IsConnected() bool {
	return p.pc.ConnectionState() == webrtc.PeerConnectionStateConnected
}
