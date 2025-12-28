package models

type Announcement struct {
	DeviceInfo
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Announce bool   `json:"announce"`
}

func (anno Announcement) GetDeviceInfo() DeviceInfo {
	return anno.DeviceInfo
}

type DeviceInfo struct {
	IP          string `json:"-"` // not part of the protocol
	Alias       string `json:"alias"`
	Version     string `json:"version"`
	DeviceModel string `json:"deviceModel,omitempty"` // nullable per protocol
	DeviceType  string `json:"deviceType,omitempty"`  // nullable per protocol
	Fingerprint string `json:"fingerprint"`
	Download    bool   `json:"download,omitempty"` // optional, default false
}

// SenderInfo extends DeviceInfo with port and protocol fields.
// Used in prepare-upload requests per protocol spec Section 4.1.
type SenderInfo struct {
	DeviceInfo
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "http" or "https"
}

func NewDeviceInfo(alias string, fingerprint string) DeviceInfo {
	return DeviceInfo{
		Alias:       alias,
		Version:     "2.1",
		DeviceModel: "LocalSend-CLI",
		DeviceType:  "headless",
		Fingerprint: fingerprint,
		Download:    false,
	}
}
