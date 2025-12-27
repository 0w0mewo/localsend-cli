package send

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync/atomic"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

type ForwardSender struct {
	baseSender
	local  *models.DeviceInfo
	remote *models.DeviceInfo
	https  bool
	abort  atomic.Bool
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
	fsp.abort.Store(false)
	fsp.session = ""
	fsp.remote = target
	fsp.https = https

	// Create local device identity for sender
	localInfo := models.NewDeviceInfo(lsutils.GenAlias(), "")
	fsp.local = &localInfo

	fsp.reset()

	return nil
}

func (fsp *ForwardSender) preUploadReq() error {
	agent := fiber.AcquireAgent()
	defer fiber.ReleaseAgent(agent)

	if fsp.https {
		// check fingerprint if https mode (See https://github.com/localsend/protocol section.2)
		certs, err := utils.FetchX509Cert(net.JoinHostPort(fsp.remote.IP, "53317"))
		if err != nil {
			return err
		}
		fingerprint := utils.SHA256ofCert(certs[0]) // only check the first cert
		if fingerprint != fsp.remote.Fingerprint {
			return constants.ErrFingerprint
		}
	}

	var meta models.PreUploadReq
	meta.Info = fsp.local
	meta.Files = fsp.files

	// setup request
	req := agent.Request()
	fsp.prepareUri(req, constants.PreuploadPath)
	req.Header.SetMethod(fiber.MethodPost)
	if fsp.pin != "" {
		req.URI().QueryArgs().Add("pin", fsp.pin)
	}
	err := agent.Parse()
	if err != nil {
		return err
	}

	// make request
	status, b, errs := agent.InsecureSkipVerify().JSON(&meta).Bytes()
	if len(errs) != 0 {
		return errs[0]
	}

	// parse error from http status
	err = constants.ParseError(status)
	if err != nil {
		return err
	}

	// decode response bytes
	var respMeta models.PreUploadResp
	err = json.Unmarshal(b, &respMeta)
	if err != nil {
		return err
	}

	fsp.session = respMeta.SessionId
	fsp.tokens = respMeta.Tokens

	return nil
}

func (fsp *ForwardSender) sendFile(fid string, ftoken string) error {
	if fsp.abort.Load() {
		return nil
	}

	fmeta, ok := fsp.files[fid]
	if !ok {
		return constants.ErrUnknown // unlikely, but check it anyway
	}

	agent := fiber.AcquireAgent()
	defer fiber.ReleaseAgent(agent)

	// prepare request
	req := agent.Request()
	fsp.prepareUri(req, constants.UploadPath)
	req.Header.SetMethod(fiber.MethodPost)
	req.URI().QueryArgs().Add("token", ftoken)
	req.URI().QueryArgs().Add("sessionId", fsp.session)
	req.URI().QueryArgs().Add("fileId", fid)
	err := agent.Parse()
	if err != nil {
		return err
	}

	// open file
	fd, err := os.Open(fmeta.FullPath)
	if err != nil {
		return err
	}
	defer fd.Close()

	// send file
	status, _, errs := agent.InsecureSkipVerify().BodyStream(fd, int(fmeta.Size)).Bytes()
	if len(errs) != 0 {
		return errs[0]
	}

	return constants.ParseError(status)
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
	agent := fiber.AcquireAgent().InsecureSkipVerify()
	defer func() {
		fsp.abort.Store(true)
		fiber.ReleaseAgent(agent)
	}()

	// prepare request
	req := agent.Request()
	fsp.prepareUri(req, constants.CancelPath)
	req.Header.SetMethod(fiber.MethodPost)
	req.URI().QueryArgs().Add("sessionId", fsp.session)
	err := agent.Parse()
	if err != nil {
		return err
	}

	// make request
	status, _, errs := agent.Bytes()
	if len(errs) != 0 {
		return errs[0]
	}

	return constants.ParseError(status)
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
