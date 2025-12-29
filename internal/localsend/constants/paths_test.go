package constants

import "testing"

func TestDeviceTypeCasing(t *testing.T) {
	tests := []struct {
		input    string
		toV3     string
		fromV3   string
	}{
		{"mobile", "MOBILE", "mobile"},
		{"desktop", "DESKTOP", "desktop"},
		{"web", "WEB", "web"},
		{"headless", "HEADLESS", "headless"},
		{"server", "SERVER", "server"},
	}

	for _, tt := range tests {
		got := DeviceTypeToV3(tt.input)
		if got != tt.toV3 {
			t.Errorf("DeviceTypeToV3(%q) = %q; want %q", tt.input, got, tt.toV3)
		}

		got = DeviceTypeFromV3(tt.toV3)
		if got != tt.fromV3 {
			t.Errorf("DeviceTypeFromV3(%q) = %q; want %q", tt.toV3, got, tt.fromV3)
		}
	}
}

func TestProtocolCasing(t *testing.T) {
	tests := []struct {
		input    string
		toV3     string
		fromV3   string
	}{
		{"http", "HTTP", "http"},
		{"https", "HTTPS", "https"},
	}

	for _, tt := range tests {
		got := ProtocolToV3(tt.input)
		if got != tt.toV3 {
			t.Errorf("ProtocolToV3(%q) = %q; want %q", tt.input, got, tt.toV3)
		}

		got = ProtocolFromV3(tt.toV3)
		if got != tt.fromV3 {
			t.Errorf("ProtocolFromV3(%q) = %q; want %q", tt.toV3, got, tt.fromV3)
		}
	}
}

func TestV3Paths(t *testing.T) {
	// Verify v3 paths are defined correctly
	paths := []struct {
		path     string
		expected string
	}{
		{NoncePathV3, "/api/localsend/v3/nonce"},
		{RegisterPathV3, "/api/localsend/v3/register"},
		{PreuploadPathV3, "/api/localsend/v3/prepare-upload"},
		{UploadPathV3, "/api/localsend/v3/upload"},
		{CancelPathV3, "/api/localsend/v3/cancel"},
		{InfoPathV3, "/api/localsend/v3/info"},
		{DownloadPathV3, "/api/localsend/v3/download"},
		{PreDownloadPathV3, "/api/localsend/v3/prepare-download"},
	}

	for _, tt := range paths {
		if tt.path != tt.expected {
			t.Errorf("Path constant = %q; want %q", tt.path, tt.expected)
		}
	}
}
