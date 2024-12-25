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
	SessionId  string            `json:"sessionId"`
	FileTokens map[string]string `json:"files"`
}

func NewPreUploadResp(sessionId string) *PreUploadResp {
	return &PreUploadResp{
		SessionId:  sessionId,
		FileTokens: make(map[string]string),
	}
}

func (pur *PreUploadResp) AddFile(fileId, token string) {
	pur.FileTokens[fileId] = token
}
