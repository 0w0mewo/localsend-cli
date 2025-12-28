package transfer

import (
	"encoding/json"
	"testing"
)

// TestParseRTCMessageNonce tests parsing of nonce messages.
func TestParseRTCMessageNonce(t *testing.T) {
	jsonData := `{"nonce":"xLJNxeKwfKvx1IYqVE_cYAUF54R547Aq6C_E_p_eilk"}`
	
	msg, msgType, err := ParseRTCMessage([]byte(jsonData))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if msgType != "nonce" {
		t.Errorf("msgType = %q; want 'nonce'", msgType)
	}
	
	nonceMsg, ok := msg.(*RTCNonceMessage)
	if !ok {
		t.Fatalf("msg is not *RTCNonceMessage")
	}
	
	if nonceMsg.Nonce != "xLJNxeKwfKvx1IYqVE_cYAUF54R547Aq6C_E_p_eilk" {
		t.Errorf("Nonce = %q; want expected value", nonceMsg.Nonce)
	}
}

// TestParseRTCMessageTokenRequest tests parsing of token request messages.
func TestParseRTCMessageTokenRequest(t *testing.T) {
	jsonData := `{"token":"sha256.abc123.def456.ed25519.sig789"}`
	
	msg, msgType, err := ParseRTCMessage([]byte(jsonData))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if msgType != "token_request" {
		t.Errorf("msgType = %q; want 'token_request'", msgType)
	}
	
	tokenMsg, ok := msg.(*RTCTokenRequest)
	if !ok {
		t.Fatalf("msg is not *RTCTokenRequest")
	}
	
	if tokenMsg.Token != "sha256.abc123.def456.ed25519.sig789" {
		t.Errorf("Token = %q; want expected value", tokenMsg.Token)
	}
}

// TestParseRTCMessageFileHeader tests parsing of file header messages.
// IMPORTANT: FileHeader has both id AND token, so it must be detected before TokenRequest.
func TestParseRTCMessageFileHeader(t *testing.T) {
	jsonData := `{"id":"0","token":"1766963574926146000"}`
	
	msg, msgType, err := ParseRTCMessage([]byte(jsonData))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if msgType != "file_header" {
		t.Errorf("msgType = %q; want 'file_header'", msgType)
	}
	
	header, ok := msg.(*RTCSendFileHeader)
	if !ok {
		t.Fatalf("msg is not *RTCSendFileHeader")
	}
	
	if header.ID != "0" {
		t.Errorf("ID = %q; want '0'", header.ID)
	}
	if header.Token != "1766963574926146000" {
		t.Errorf("Token = %q; want '1766963574926146000'", header.Token)
	}
}

// TestParseRTCMessageFileList tests parsing of file list messages.
func TestParseRTCMessageFileList(t *testing.T) {
	jsonData := `{"status":"OK","files":[{"id":"0","fileName":"test.md","size":1024,"fileType":"text/markdown"}]}`
	
	msg, msgType, err := ParseRTCMessage([]byte(jsonData))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if msgType != "file_list" {
		t.Errorf("msgType = %q; want 'file_list'", msgType)
	}
	
	fileList, ok := msg.(*RTCPinSendingResponse)
	if !ok {
		t.Fatalf("msg is not *RTCPinSendingResponse")
	}
	
	if fileList.Status != "OK" {
		t.Errorf("Status = %q; want 'OK'", fileList.Status)
	}
	if len(fileList.Files) != 1 {
		t.Errorf("len(Files) = %d; want 1", len(fileList.Files))
	}
	if fileList.Files[0].FileName != "test.md" {
		t.Errorf("Files[0].FileName = %q; want 'test.md'", fileList.Files[0].FileName)
	}
}

// TestParseRTCMessagePin tests parsing of PIN messages.
func TestParseRTCMessagePin(t *testing.T) {
	jsonData := `{"pin":"123456"}`
	
	msg, msgType, err := ParseRTCMessage([]byte(jsonData))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if msgType != "pin" {
		t.Errorf("msgType = %q; want 'pin'", msgType)
	}
	
	pinMsg, ok := msg.(*RTCPinMessage)
	if !ok {
		t.Fatalf("msg is not *RTCPinMessage")
	}
	
	if pinMsg.Pin != "123456" {
		t.Errorf("Pin = %q; want '123456'", pinMsg.Pin)
	}
}

// TestParseRTCMessageUnknown tests that unknown messages return nil.
func TestParseRTCMessageUnknown(t *testing.T) {
	jsonData := `{"unknown":"field"}`
	
	msg, msgType, err := ParseRTCMessage([]byte(jsonData))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if msg != nil {
		t.Errorf("msg = %v; want nil", msg)
	}
	if msgType != "" {
		t.Errorf("msgType = %q; want empty string", msgType)
	}
}

// TestRTCFileListResponseSerialization tests JSON serialization of file list response.
func TestRTCFileListResponseSerialization(t *testing.T) {
	response := RTCFileListResponse{
		Status: "OK",
		Files:  map[string]string{"0": "token123", "1": "token456"},
	}
	
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}
	
	var parsed RTCFileListResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	
	if parsed.Status != "OK" {
		t.Errorf("Status = %q; want 'OK'", parsed.Status)
	}
	if len(parsed.Files) != 2 {
		t.Errorf("len(Files) = %d; want 2", len(parsed.Files))
	}
	if parsed.Files["0"] != "token123" {
		t.Errorf("Files['0'] = %q; want 'token123'", parsed.Files["0"])
	}
}

// TestRTCNonceMessageSerialization tests JSON serialization of nonce message.
func TestRTCNonceMessageSerialization(t *testing.T) {
	nonce := RTCNonceMessage{Nonce: "test-nonce-base64"}
	
	data, err := json.Marshal(nonce)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}
	
	expected := `{"nonce":"test-nonce-base64"}`
	if string(data) != expected {
		t.Errorf("Serialized = %q; want %q", string(data), expected)
	}
}

// TestRTCTokenResponseSerialization tests JSON serialization of token response.
func TestRTCTokenResponseSerialization(t *testing.T) {
	tests := []struct {
		name     string
		response RTCTokenResponse
		expected string
	}{
		{
			name:     "OK response",
			response: RTCTokenResponse{Status: "OK", Token: "sha256.abc"},
			expected: `{"status":"OK","token":"sha256.abc"}`,
		},
		{
			name:     "PIN_REQUIRED response",
			response: RTCTokenResponse{Status: "PIN_REQUIRED", Token: "sha256.def"},
			expected: `{"status":"PIN_REQUIRED","token":"sha256.def"}`,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.response)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}
			if string(data) != tt.expected {
				t.Errorf("Serialized = %q; want %q", string(data), tt.expected)
			}
		})
	}
}

// TestFileHeaderVsTokenRequestParsing ensures file headers are parsed correctly
// instead of being misidentified as token requests (critical for protocol correctness).
func TestFileHeaderVsTokenRequestParsing(t *testing.T) {
	// This message has both "id" and "token" - must be file_header, not token_request
	fileHeaderJSON := `{"id":"0","token":"1766963574926146000"}`
	
	// This message has only "token" - must be token_request
	tokenRequestJSON := `{"token":"sha256.hash.salt.ed25519.sig"}`
	
	// Test file header
	msg1, type1, _ := ParseRTCMessage([]byte(fileHeaderJSON))
	if type1 != "file_header" {
		t.Errorf("File header parsed as %q; want 'file_header'", type1)
	}
	if _, ok := msg1.(*RTCSendFileHeader); !ok {
		t.Error("File header not parsed as RTCSendFileHeader")
	}
	
	// Test token request
	msg2, type2, _ := ParseRTCMessage([]byte(tokenRequestJSON))
	if type2 != "token_request" {
		t.Errorf("Token request parsed as %q; want 'token_request'", type2)
	}
	if _, ok := msg2.(*RTCTokenRequest); !ok {
		t.Error("Token request not parsed as RTCTokenRequest")
	}
}
