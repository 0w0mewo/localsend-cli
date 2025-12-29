package models

// NonceRequest represents a request to obtain a nonce for token generation.
// Used in v3 protocol nonce exchange endpoint.
type NonceRequest struct {
	Nonce string `json:"nonce"`
}

// NonceResponse represents the server's response containing a nonce.
// Used in v3 protocol nonce exchange endpoint.
type NonceResponse struct {
	Nonce string `json:"nonce"`
}

// RegisterRequestV3 represents a device registration request in the v3 protocol.
// This is sent to /api/localsend/v3/register to establish a session.
type RegisterRequestV3 struct {
	Alias           string `json:"alias"`
	Version         string `json:"version"`
	DeviceModel     string `json:"deviceModel,omitempty"`
	DeviceType      string `json:"deviceType,omitempty"`
	Token           string `json:"token"`
	Port            int    `json:"port"`
	Protocol        string `json:"protocol"` // "http" or "https"
	HasWebInterface bool   `json:"hasWebInterface,omitempty"`
}

// RegisterResponseV3 represents a device registration response in the v3 protocol.
// Returned from /api/localsend/v3/register endpoint.
type RegisterResponseV3 struct {
	Alias           string `json:"alias"`
	Version         string `json:"version"`
	DeviceModel     string `json:"deviceModel,omitempty"`
	DeviceType      string `json:"deviceType,omitempty"`
	Token           string `json:"token"`
	HasWebInterface bool   `json:"hasWebInterface,omitempty"`
}
