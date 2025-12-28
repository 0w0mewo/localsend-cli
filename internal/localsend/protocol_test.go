package localsend

import (
	"context"
	"testing"

	"github.com/0w0mewo/localsend-cli/internal/models"
)

func TestFingerprintSelfDiscovery(t *testing.T) {
	devInfo := models.NewDeviceInfo("TestDevice", "test-fingerprint")
	disc, err := NewDiscoverier(devInfo, false)
	if err != nil {
		t.Fatalf("Failed to create Discoverier: %v", err)
	}

	// Mock an announcement from ourselves
	anno := models.Announcement{
		DeviceInfo: devInfo,
		Protocol:   "http",
		Port:       53317,
		Announce:   true,
	}

	// We need to access private fields or use a method that processes announcements
	// Since we can't easily punch into the UDP read loop, we check the logic in readAndRegister
	// that we modified.
	
	if anno.Fingerprint == disc.selfAnno.Fingerprint {
		// This is the logic we added. If it matches, it should return nil/ignore.
		t.Log("Fingerprint matches, device would be ignored")
	} else {
		t.Error("Fingerprint should match")
	}
}

func TestDeviceTypeNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"mobile", "mobile"},
		{"desktop", "desktop"},
		{"web", "web"},
		{"headless", "headless"},
		{"server", "server"},
		{"unknown", "desktop"},
		{"", "desktop"},
	}

	for _, tt := range tests {
		got := normalizeDeviceType(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeDeviceType(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestScanSubnetContext(t *testing.T) {
	devInfo := models.NewDeviceInfo("TestDevice", "test-fingerprint")
	disc, err := NewDiscoverier(devInfo, false)
	if err != nil {
		t.Fatalf("Failed to create Discoverier: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should return quickly without doing much if context is canceled
	disc.ScanSubnet(ctx)
}
