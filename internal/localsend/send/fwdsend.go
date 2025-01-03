package send

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
)

var httpClient = lsutils.HttpClient

type ForwardSender struct {
	baseSender
	remote *models.DeviceInfo
	https  bool
	abort  bool
}

func NewForwardSender() *ForwardSender {
	return &ForwardSender{
		baseSender: baseSender{
			files:  make(map[string]models.FileMeta),
			tokens: make(map[string]string),
		},
	}
}

func (fsp *ForwardSender) Init(target *models.DeviceInfo, https bool) error {
	fsp.abort = false
	fsp.session = ""
	fsp.remote = target
	fsp.https = https

	fsp.reset()

	return nil
}

func (fsp *ForwardSender) preUploadReq() error {
	scheme := "http"
	if fsp.https {
		scheme = "https"
	}
	remoteAddr := net.JoinHostPort(fsp.remote.IP, "53317")
	base := filepath.Join(remoteAddr, constants.PreuploadPath)

	var pinQuery string
	if fsp.pin != "" {
		pinQuery = "?pin=" + fsp.pin
	}
	url := fmt.Sprintf("%s://%s%s", scheme, base, pinQuery)

	if fsp.https {
		// check fingerprint if https mode (See https://github.com/localsend/protocol section.2)
		certs, err := utils.FetchX509Cert(remoteAddr)
		if err != nil {
			return err
		}
		fingerprint := utils.SHA256ofCert(certs[0]) // only check the first cert
		if fingerprint != fsp.remote.Fingerprint {
			return constants.ErrFingerprint
		}
	}

	var meta models.PreUploadReq
	meta.Info = fsp.remote
	meta.Files = fsp.files

	buffer := bytes.NewBuffer(nil)
	err := json.NewEncoder(buffer).Encode(&meta)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, buffer)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	err = constants.ParseError(resp.StatusCode)
	if err != nil {
		return err
	}

	var respMeta models.PreUploadResp
	err = json.NewDecoder(resp.Body).Decode(&respMeta)
	if err != nil {
		return err
	}

	fsp.session = respMeta.SessionId
	fsp.tokens = respMeta.Tokens

	return nil
}

func (fsp *ForwardSender) sendFile(fid string, ftoken string) error {
	if fsp.abort {
		return nil
	}

	scheme := "http"
	if fsp.https {
		scheme = "https"
	}
	remoteAddr := net.JoinHostPort(fsp.remote.IP, "53317")
	base := filepath.Join(remoteAddr, constants.UploadPath)
	url := fmt.Sprintf("%s://%s?sessionId=%s&fileId=%s&token=%s", scheme, base, fsp.session, fid, ftoken)

	fmeta, ok := fsp.files[fid]
	if !ok {
		return constants.ErrUnknown // unlikely, but check it anyway
	}

	fd, err := os.Open(fmeta.FullPath)
	if err != nil {
		return err
	}
	defer fd.Close()

	req, err := http.NewRequest(http.MethodPost, url, fd)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return constants.ParseError(resp.StatusCode)
}

func (fsp *ForwardSender) Start() error {
	err := fsp.preUploadReq()
	if err != nil {
		return fmt.Errorf("PreUpload %v", err)
	}

	for fid, ftoken := range fsp.tokens {
		err := fsp.sendFile(fid, ftoken)
		if err != nil {
			slog.Error("Fail to send file", "error", err, "fileId", fid)
			continue
		}
	}

	return nil
}

func (fsp *ForwardSender) Cancel() error {
	scheme := "http"
	if fsp.https {
		scheme = "https"
	}
	remoteAddr := net.JoinHostPort(fsp.remote.IP, "53317")
	base := filepath.Join(remoteAddr, constants.CancelPath)
	url := fmt.Sprintf("%s://%s?sessionId=%s", scheme, base, fsp.session)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		resp.Body.Close()
		fsp.abort = true
	}()

	return constants.ParseError(resp.StatusCode)
}
