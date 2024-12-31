package models

type PreUploadReq struct {
	Info  *DeviceInfo `json:"info"`
	Files FileMetas   `json:"files"`
}

type PreDownloadResp struct {
	PreUploadReq
	SessionId string `json:"sessionId"`
}

func NewPreDownloadResp(sessionId string) *PreDownloadResp {
	return &PreDownloadResp{
		SessionId: sessionId,
	}
}

type FileMetas map[string]FileMeta

type PreUploadResp struct {
	SessionId string     `json:"sessionId"`
	Tokens    FileTokens `json:"files"`
}

type FileTokens map[string]string
