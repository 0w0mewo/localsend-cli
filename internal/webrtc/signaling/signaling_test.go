package signaling

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestSdpCompressDecompress(t *testing.T) {
	original := `v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:abcd
a=ice-pwd:efghijklmnop
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF
a=setup:actpass
a=mid:0
a=sctp-port:5000`

	compressed, err := CompressSDP(original)
	if err != nil {
		t.Fatalf("CompressSDP failed: %v", err)
	}

	if compressed == "" {
		t.Error("Compressed SDP is empty")
	}

	// Verify compressed is smaller than original (should be for repeated patterns)
	if len(compressed) >= len(original) {
		t.Logf("Warning: compressed (%d) not smaller than original (%d)", len(compressed), len(original))
	}

	decompressed, err := DecompressSDP(compressed)
	if err != nil {
		t.Fatalf("DecompressSDP failed: %v", err)
	}

	if decompressed != original {
		t.Errorf("Round-trip failed.\nOriginal: %q\nDecompressed: %q", original, decompressed)
	}
}

func TestWsServerMessageHelloSerialization(t *testing.T) {
	clientID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	peerID := uuid.MustParse("00000000-0000-0000-0000-000000000002")

	msg := WsServerMessage{
		Type: "HELLO",
		Client: &ClientInfo{
			ID:          clientID,
			Alias:       "Test Client",
			Version:     "2.1",
			DeviceModel: "Test",
			DeviceType:  "desktop",
			Token:       "abc123",
		},
		Peers: &[]ClientInfo{
			{
				ID:          peerID,
				Alias:       "Peer",
				Version:     "2.1",
				DeviceModel: "Phone",
				DeviceType:  "mobile",
				Token:       "def456",
			},
		},
	}

	bytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed WsServerMessage
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if parsed.Type != "HELLO" {
		t.Errorf("Type = %q; want HELLO", parsed.Type)
	}
	if parsed.Client.Alias != "Test Client" {
		t.Errorf("Client.Alias = %q; want 'Test Client'", parsed.Client.Alias)
	}
	if parsed.Peers == nil {
		t.Fatal("Peers is nil")
	}
	if len(*parsed.Peers) != 1 {
		t.Errorf("Peers count = %d; want 1", len(*parsed.Peers))
	}
}

func TestWsClientMessageOfferSerialization(t *testing.T) {
	targetID := uuid.MustParse("00000000-0000-0000-0000-000000000002")

	msg := NewOfferMessage("session-123", targetID, "compressed-sdp")

	bytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Verify JSON structure
	var raw map[string]interface{}
	if err := json.Unmarshal(bytes, &raw); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if raw["type"] != "OFFER" {
		t.Errorf("type = %q; want OFFER", raw["type"])
	}
	if raw["sessionId"] != "session-123" {
		t.Errorf("sessionId = %q; want 'session-123'", raw["sessionId"])
	}
}

func TestClientInfoToAnnouncement(t *testing.T) {
	info := ClientInfo{
		ID:          uuid.New(),
		Alias:       "Test Device",
		Version:     "2.1",
		DeviceModel: "MacBook",
		DeviceType:  "desktop",
		Token:       "fingerprint-abc",
	}

	anno := info.ToAnnouncement()

	if anno.Alias != "Test Device" {
		t.Errorf("Alias = %q; want 'Test Device'", anno.Alias)
	}
	if anno.DeviceModel != "MacBook" {
		t.Errorf("DeviceModel = %q; want 'MacBook'", anno.DeviceModel)
	}
	if anno.Protocol != "webrtc" {
		t.Errorf("Protocol = %q; want 'webrtc'", anno.Protocol)
	}
	if anno.Fingerprint != "fingerprint-abc" {
		t.Errorf("Fingerprint = %q; want 'fingerprint-abc'", anno.Fingerprint)
	}
}

// =============================================================================
// Rust Test Vectors
// These tests verify exact JSON format compatibility with the official Rust implementation.
// =============================================================================

// TestRustVectorHelloMessage verifies exact JSON format from Rust tests.
func TestRustVectorHelloMessage(t *testing.T) {
	// From Rust: ws_server_hello_message_encoding (signaling.rs)
	expected := `{"type":"HELLO","client":{"id":"00000000-0000-0000-0000-000000000000","alias":"Cute Apple","version":"2.3","deviceModel":"Dell","deviceType":"desktop","token":"123"},"peers":[]}`

	msg := WsServerMessage{
		Type: "HELLO",
		Client: &ClientInfo{
			ID:          uuid.MustParse("00000000-0000-0000-0000-000000000000"),
			Alias:       "Cute Apple",
			Version:     "2.3",
			DeviceModel: "Dell",
			DeviceType:  "desktop",
			Token:       "123",
		},
		Peers: &[]ClientInfo{},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if string(data) != expected {
		t.Errorf("JSON mismatch.\nGot:  %s\nWant: %s", string(data), expected)
	}

	// Verify round-trip
	var parsed WsServerMessage
	if err := json.Unmarshal([]byte(expected), &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if parsed.Client.Alias != "Cute Apple" {
		t.Errorf("Parsed alias = %q; want 'Cute Apple'", parsed.Client.Alias)
	}
}

// TestRustVectorOfferMessage verifies exact JSON format from Rust tests.
func TestRustVectorOfferMessage(t *testing.T) {
	// From Rust: ws_server_offer_message_encoding (signaling.rs)
	// Note: deviceModel is omitted when empty
	expected := `{"type":"OFFER","peer":{"id":"00000000-0000-0000-0000-000000000000","alias":"Cute Apple","version":"2.3","deviceType":"desktop","token":"123"},"sessionId":"456","sdp":"my-sdp"}`

	msg := WsServerMessage{
		Type: "OFFER",
		Peer: &ClientInfo{
			ID:          uuid.MustParse("00000000-0000-0000-0000-000000000000"),
			Alias:       "Cute Apple",
			Version:     "2.3",
			DeviceModel: "", // Empty - should be omitted
			DeviceType:  "desktop",
			Token:       "123",
		},
		SessionID: "456",
		SDP:       "my-sdp",
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if string(data) != expected {
		t.Errorf("JSON mismatch.\nGot:  %s\nWant: %s", string(data), expected)
	}
}

// TestRustVectorClientUpdateMessage verifies exact JSON format from Rust tests.
func TestRustVectorClientUpdateMessage(t *testing.T) {
	// From Rust: ws_client_update_message_encoding (signaling.rs)
	expected := `{"type":"UPDATE","info":{"alias":"Cute Apple","version":"2.3","deviceModel":"Dell","deviceType":"desktop","token":"123"}}`

	msg := WsClientMessage{
		Type: "UPDATE",
		Info: &ClientInfoWithoutID{
			Alias:       "Cute Apple",
			Version:     "2.3",
			DeviceModel: "Dell",
			DeviceType:  "desktop",
			Token:       "123",
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if string(data) != expected {
		t.Errorf("JSON mismatch.\nGot:  %s\nWant: %s", string(data), expected)
	}

	// Verify round-trip
	var parsed WsClientMessage
	if err := json.Unmarshal([]byte(expected), &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if parsed.Info.Alias != "Cute Apple" {
		t.Errorf("Parsed alias = %q; want 'Cute Apple'", parsed.Info.Alias)
	}
}

// TestWsServerJoinMessage verifies JOIN message serialization.
func TestWsServerJoinMessage(t *testing.T) {
	peerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	msg := WsServerMessage{
		Type: "JOIN",
		Peer: &ClientInfo{
			ID:          peerID,
			Alias:       "New Peer",
			Version:     "2.1",
			DeviceModel: "iPhone",
			DeviceType:  "mobile",
			Token:       "token123",
		},
	}

	// Marshal/unmarshal round trip
	bytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed WsServerMessage
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify all fields
	if parsed.Type != "JOIN" {
		t.Errorf("Type = %q; want JOIN", parsed.Type)
	}
	if parsed.Peer == nil {
		t.Fatal("Peer is nil")
	}
	if parsed.Peer.ID != peerID {
		t.Errorf("Peer.ID = %v; want %v", parsed.Peer.ID, peerID)
	}
	if parsed.Peer.Alias != "New Peer" {
		t.Errorf("Peer.Alias = %q; want 'New Peer'", parsed.Peer.Alias)
	}
	if parsed.Peer.Version != "2.1" {
		t.Errorf("Peer.Version = %q; want '2.1'", parsed.Peer.Version)
	}
	if parsed.Peer.DeviceModel != "iPhone" {
		t.Errorf("Peer.DeviceModel = %q; want 'iPhone'", parsed.Peer.DeviceModel)
	}
	if parsed.Peer.DeviceType != "mobile" {
		t.Errorf("Peer.DeviceType = %q; want 'mobile'", parsed.Peer.DeviceType)
	}
	if parsed.Peer.Token != "token123" {
		t.Errorf("Peer.Token = %q; want 'token123'", parsed.Peer.Token)
	}
}

// TestWsServerLeftMessage verifies LEFT message serialization.
func TestWsServerLeftMessage(t *testing.T) {
	peerID := uuid.MustParse("00000000-0000-0000-0000-000000000002")

	msg := WsServerMessage{
		Type:   "LEFT",
		PeerID: &peerID,
	}

	// Marshal/unmarshal round trip
	bytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed WsServerMessage
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify PeerID is preserved
	if parsed.Type != "LEFT" {
		t.Errorf("Type = %q; want LEFT", parsed.Type)
	}
	if parsed.PeerID == nil {
		t.Fatal("PeerID is nil")
	}
	if *parsed.PeerID != peerID {
		t.Errorf("PeerID = %v; want %v", *parsed.PeerID, peerID)
	}
}

// TestWsServerErrorMessage verifies ERROR message serialization.
func TestWsServerErrorMessage(t *testing.T) {
	msg := WsServerMessage{
		Type: "ERROR",
		Code: 400,
	}

	// Marshal/unmarshal round trip
	bytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed WsServerMessage
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify Code is preserved
	if parsed.Type != "ERROR" {
		t.Errorf("Type = %q; want ERROR", parsed.Type)
	}
	if parsed.Code != 400 {
		t.Errorf("Code = %d; want 400", parsed.Code)
	}
}

// TestWsServerUpdateMessage verifies server UPDATE message serialization.
func TestWsServerUpdateMessage(t *testing.T) {
	peerID := uuid.MustParse("00000000-0000-0000-0000-000000000003")

	msg := WsServerMessage{
		Type: "UPDATE",
		Peer: &ClientInfo{
			ID:          peerID,
			Alias:       "Updated Peer",
			Version:     "2.2",
			DeviceModel: "Galaxy",
			DeviceType:  "mobile",
			Token:       "updated-token",
		},
	}

	// Marshal/unmarshal round trip
	bytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed WsServerMessage
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify all fields
	if parsed.Type != "UPDATE" {
		t.Errorf("Type = %q; want UPDATE", parsed.Type)
	}
	if parsed.Peer == nil {
		t.Fatal("Peer is nil")
	}
	if parsed.Peer.ID != peerID {
		t.Errorf("Peer.ID = %v; want %v", parsed.Peer.ID, peerID)
	}
	if parsed.Peer.Alias != "Updated Peer" {
		t.Errorf("Peer.Alias = %q; want 'Updated Peer'", parsed.Peer.Alias)
	}
	if parsed.Peer.Version != "2.2" {
		t.Errorf("Peer.Version = %q; want '2.2'", parsed.Peer.Version)
	}
}

// TestWsServerAnswerMessage verifies ANSWER message serialization.
func TestWsServerAnswerMessage(t *testing.T) {
	peerID := uuid.MustParse("00000000-0000-0000-0000-000000000004")

	msg := WsServerMessage{
		Type: "ANSWER",
		Peer: &ClientInfo{
			ID:          peerID,
			Alias:       "Answering Peer",
			Version:     "2.1",
			DeviceModel: "MacBook",
			DeviceType:  "desktop",
			Token:       "answer-token",
		},
		SessionID: "session-456",
		SDP:       "compressed-answer-sdp",
	}

	// Marshal/unmarshal round trip
	bytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed WsServerMessage
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify all fields
	if parsed.Type != "ANSWER" {
		t.Errorf("Type = %q; want ANSWER", parsed.Type)
	}
	if parsed.Peer == nil {
		t.Fatal("Peer is nil")
	}
	if parsed.Peer.Alias != "Answering Peer" {
		t.Errorf("Peer.Alias = %q; want 'Answering Peer'", parsed.Peer.Alias)
	}
	if parsed.SessionID != "session-456" {
		t.Errorf("SessionID = %q; want 'session-456'", parsed.SessionID)
	}
	if parsed.SDP != "compressed-answer-sdp" {
		t.Errorf("SDP = %q; want 'compressed-answer-sdp'", parsed.SDP)
	}
}

// TestClientInfoWithoutIDOmitEmpty verifies empty field omission.
func TestClientInfoWithoutIDOmitEmpty(t *testing.T) {
	msg := WsClientMessage{
		Type: "UPDATE",
		Info: &ClientInfoWithoutID{
			Alias:       "Test Device",
			Version:     "2.1",
			DeviceModel: "", // Empty - should be omitted
			DeviceType:  "", // Empty - should be omitted
			Token:       "abc123",
		},
	}

	// Marshal and verify these fields are NOT in the JSON output
	bytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	jsonStr := string(bytes)

	// Verify deviceModel and deviceType are not present
	var raw map[string]interface{}
	if err := json.Unmarshal(bytes, &raw); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	info, ok := raw["info"].(map[string]interface{})
	if !ok {
		t.Fatal("info field is not an object")
	}

	if _, exists := info["deviceModel"]; exists {
		t.Errorf("deviceModel should be omitted when empty, but found in JSON: %s", jsonStr)
	}
	if _, exists := info["deviceType"]; exists {
		t.Errorf("deviceType should be omitted when empty, but found in JSON: %s", jsonStr)
	}

	// Verify required fields are present
	if info["alias"] != "Test Device" {
		t.Errorf("alias = %v; want 'Test Device'", info["alias"])
	}
	if info["version"] != "2.1" {
		t.Errorf("version = %v; want '2.1'", info["version"])
	}
	if info["token"] != "abc123" {
		t.Errorf("token = %v; want 'abc123'", info["token"])
	}
}

// TestWsServerHelloWithMultiplePeers verifies HELLO with peers array.
func TestWsServerHelloWithMultiplePeers(t *testing.T) {
	clientID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	peer1ID := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	peer2ID := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	peer3ID := uuid.MustParse("00000000-0000-0000-0000-000000000004")

	msg := WsServerMessage{
		Type: "HELLO",
		Client: &ClientInfo{
			ID:          clientID,
			Alias:       "My Device",
			Version:     "2.1",
			DeviceModel: "Desktop",
			DeviceType:  "desktop",
			Token:       "my-token",
		},
		Peers: &[]ClientInfo{
			{
				ID:          peer1ID,
				Alias:       "Peer One",
				Version:     "2.1",
				DeviceModel: "iPhone",
				DeviceType:  "mobile",
				Token:       "token1",
			},
			{
				ID:          peer2ID,
				Alias:       "Peer Two",
				Version:     "2.2",
				DeviceModel: "Android",
				DeviceType:  "mobile",
				Token:       "token2",
			},
			{
				ID:          peer3ID,
				Alias:       "Peer Three",
				Version:     "2.1",
				DeviceModel: "MacBook",
				DeviceType:  "desktop",
				Token:       "token3",
			},
		},
	}

	// Marshal/unmarshal round trip
	bytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed WsServerMessage
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify all peers are preserved after round trip
	if parsed.Type != "HELLO" {
		t.Errorf("Type = %q; want HELLO", parsed.Type)
	}
	if parsed.Client == nil {
		t.Fatal("Client is nil")
	}
	if parsed.Client.Alias != "My Device" {
		t.Errorf("Client.Alias = %q; want 'My Device'", parsed.Client.Alias)
	}
	if parsed.Peers == nil {
		t.Fatal("Peers is nil")
	}
	if len(*parsed.Peers) != 3 {
		t.Fatalf("Peers count = %d; want 3", len(*parsed.Peers))
	}

	peers := *parsed.Peers

	// Verify first peer
	if peers[0].ID != peer1ID {
		t.Errorf("Peer[0].ID = %v; want %v", peers[0].ID, peer1ID)
	}
	if peers[0].Alias != "Peer One" {
		t.Errorf("Peer[0].Alias = %q; want 'Peer One'", peers[0].Alias)
	}

	// Verify second peer
	if peers[1].ID != peer2ID {
		t.Errorf("Peer[1].ID = %v; want %v", peers[1].ID, peer2ID)
	}
	if peers[1].Alias != "Peer Two" {
		t.Errorf("Peer[1].Alias = %q; want 'Peer Two'", peers[1].Alias)
	}

	// Verify third peer
	if peers[2].ID != peer3ID {
		t.Errorf("Peer[2].ID = %v; want %v", peers[2].ID, peer3ID)
	}
	if peers[2].Alias != "Peer Three" {
		t.Errorf("Peer[2].Alias = %q; want 'Peer Three'", peers[2].Alias)
	}
}

