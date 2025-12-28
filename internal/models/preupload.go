package models

// PreUploadReq is the request body for POST /api/localsend/v2/prepare-upload
// Per protocol spec Section 4.1, info must include port and protocol.
type PreUploadReq struct {
	Info  *SenderInfo `json:"info"`
	Files FileMetas   `json:"files"`
}

// PreDownloadResp is the response body for POST /api/localsend/v2/prepare-download
// Per protocol spec Section 5.2, info does NOT include port and protocol.
type PreDownloadResp struct {
	Info      *DeviceInfo `json:"info"`
	SessionId string      `json:"sessionId"`
	Files     FileMetas   `json:"files"`
}

type FileMetas map[string]FileMeta

type PreUploadResp struct {
	SessionId string     `json:"sessionId"`
	Tokens    FileTokens `json:"files"`
}

type FileTokens map[string]string
