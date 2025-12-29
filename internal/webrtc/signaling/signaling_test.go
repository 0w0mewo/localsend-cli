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
		Peers: []ClientInfo{
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
	if len(parsed.Peers) != 1 {
		t.Errorf("Peers count = %d; want 1", len(parsed.Peers))
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
		Peers: []ClientInfo{},
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

