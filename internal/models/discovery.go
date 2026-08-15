package models

type Announcement struct {
	DeviceInfo
	Announce bool `json:"announce"`
}

func (anno Announcement) GetDeviceInfo() DeviceInfo {
	return anno.DeviceInfo
}

type DeviceInfo struct {
	IP          string `json:"-"` // not part of the protocol
	Alias       string `json:"alias"`
	Version     string `json:"version"`
	DeviceModel string `json:"deviceModel"`
	DeviceType  string `json:"deviceType"`
	Fingerprint string `json:"fingerprint"`
	Download    bool   `json:"download"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
}

func NewDeviceInfo(alias string, fingerprint string) DeviceInfo {
	return DeviceInfo{
		Alias:       alias,
		Version:     "2.0",
		DeviceModel: "LocalSend-CLI",
		DeviceType:  "headless",
		Fingerprint: fingerprint,
		Protocol:    "https",
		Port:        53317,
		Download:    false,
	}
}
