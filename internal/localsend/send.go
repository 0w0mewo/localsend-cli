package localsend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"

	lserrors "github.com/0w0mewo/localsend-cli/internal/localsend/errors"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
)

type FileSender struct {
	remote  *models.DeviceInfo
	tokens  map[string]string
	files   map[string]models.FileMeta
	session string
	https   bool
	abort   bool
}

func NewFileSender() *FileSender {
	return &FileSender{
		files:  make(map[string]models.FileMeta),
		tokens: make(map[string]string),
	}
}

func (fsp *FileSender) Init(target *models.DeviceInfo, https bool) error {
	fsp.abort = false
	fsp.session = ""

	for k := range fsp.tokens {
		delete(fsp.tokens, k)
	}

	for k := range fsp.files {
		delete(fsp.files, k)
	}

	fsp.remote = target
	fsp.https = https

	return nil
}

func (fsp *FileSender) AddFile(filePath string) error {
	if fsp.files == nil {
		fsp.files = make(map[string]models.FileMeta)
	}

	fileMeta, err := models.GenFileMeta(filePath)
	if err != nil {
		return err
	}

	fsp.files[fileMeta.Id] = fileMeta
	return nil
}

func (fsp *FileSender) AddDir(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		return fsp.AddFile(path)
	})
}

func (fsp *FileSender) preUploadReq() error {
	scheme := "http"
	if fsp.https {
		scheme = "https"
	}
	remoteAddr := net.JoinHostPort(fsp.remote.IP, "53317")
	base := filepath.Join(remoteAddr, PreuploadPath)
	url := fmt.Sprintf("%s://%s", scheme, base)

	if fsp.https {
		// check fingerprint if https mode (See https://github.com/localsend/protocol section.2)
		certs, err := utils.FetchX509Cert(remoteAddr)
		if err != nil {
			return err
		}
		fingerprint := utils.SHA256ofCert(certs[0]) // only check the first cert
		if fingerprint != fsp.remote.Fingerprint {
			return lserrors.ErrFingerprint
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

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	err = lserrors.ParseError(resp.StatusCode)
	if err != nil {
		return err
	}

	var respMeta models.PreUploadResp
	err = json.NewDecoder(resp.Body).Decode(&respMeta)
	if err != nil {
		return err
	}

	fsp.session = respMeta.SessionId
	fsp.tokens = respMeta.FileTokens

	return nil
}

func (fsp *FileSender) sendFile(fid string, ftoken string) error {
	if fsp.abort {
		return nil
	}

	scheme := "http"
	if fsp.https {
		scheme = "https"
	}
	remoteAddr := net.JoinHostPort(fsp.remote.IP, "53317")
	base := filepath.Join(remoteAddr, UploadPath)
	url := fmt.Sprintf("%s://%s?sessionId=%s&fileId=%s&token=%s", scheme, base, fsp.session, fid, ftoken)

	fmeta, ok := fsp.files[fid]
	if !ok {
		return lserrors.ErrUnknown // unlikely, but check it anyway
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

	return lserrors.ParseError(resp.StatusCode)
}

func (fsp *FileSender) Start() error {
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

func (fsp *FileSender) Cancel() error {
	scheme := "http"
	if fsp.https {
		scheme = "https"
	}
	remoteAddr := net.JoinHostPort(fsp.remote.IP, "53317")
	base := filepath.Join(remoteAddr, CancelPath)
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

	return lserrors.ParseError(resp.StatusCode)
}
