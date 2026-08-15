package send

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

type ForwardSender struct {
	baseSender
	remote     *models.DeviceInfo
	https      bool
	abort      bool
	httpclient *fasthttp.Client
}

func NewForwardSender(httpclient *fasthttp.Client) *ForwardSender {
	return &ForwardSender{
		baseSender: baseSender{
			files:  make(map[string]models.FileMeta),
			tokens: make(map[string]string),
		},
		httpclient: httpclient,
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
	var meta models.PreUploadReq
	meta.Info = fsp.remote
	meta.Files = fsp.files
	metaJson, err := json.Marshal(&meta)
	if err != nil {
		return err
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// setup request
	fsp.prepareUri(req, constants.PreuploadPath)
	req.Header.SetMethod(fiber.MethodPost)
	req.SetBodyRaw(metaJson)
	if fsp.pin != "" {
		req.URI().QueryArgs().Add("pin", fsp.pin)
	}

	println(string(req.URI().FullURI()))

	// make request
	err = fsp.httpclient.Do(req, resp)
	if err != nil {
		return err
	}

	// parse error from http status
	err = constants.ParseError(resp.StatusCode())
	if err != nil {
		return err
	}

	// decode response bytes
	var respMeta models.PreUploadResp
	err = json.Unmarshal(resp.Body(), &respMeta)
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

	fmeta, ok := fsp.files[fid]
	if !ok {
		return constants.ErrUnknown // unlikely, but check it anyway
	}

	// open file
	fd, err := os.Open(fmeta.FullPath)
	if err != nil {
		return err
	}
	defer fd.Close()

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// prepare request
	fsp.prepareUri(req, constants.UploadPath)
	req.Header.SetMethod(fiber.MethodPost)
	req.URI().QueryArgs().Add("token", ftoken)
	req.URI().QueryArgs().Add("sessionId", fsp.session)
	req.URI().QueryArgs().Add("fileId", fid)
	req.SetBodyStream(fd, int(fmeta.Size))

	// send file

	err = fsp.httpclient.Do(req, resp)
	if err != nil {
		return err
	}

	return constants.ParseError(resp.StatusCode())
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
	defer func() {
		fsp.abort = true
	}()

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// prepare request
	fsp.prepareUri(req, constants.CancelPath)
	req.Header.SetMethod(fiber.MethodPost)
	req.URI().QueryArgs().Add("sessionId", fsp.session)

	// make request
	err := fsp.httpclient.Do(req, resp)
	if err != nil {
		return err
	}

	return constants.ParseError(resp.StatusCode())
}

func (fsp *ForwardSender) prepareUri(req *fasthttp.Request, path string) {
	remoteAddr := net.JoinHostPort(fsp.remote.IP, "53317")

	req.Header.SetUserAgent("localsend-cli")
	req.URI().SetPath(path)
	if fsp.https {
		req.URI().SetScheme("https")
	} else {
		req.URI().SetScheme("http")
	}
	req.URI().SetHost(remoteAddr)
}
