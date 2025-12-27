package send

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/0w0mewo/localsend-cli/templates"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type DownloadEntry struct {
	Filename string
	Url      string
}

type ReverseSender struct {
	baseSender
	local     *models.DeviceInfo
	webServer *fiber.App
	downloads []DownloadEntry
	https     bool
	cert      tls.Certificate
}

func NewReverseSender() *ReverseSender {
	return &ReverseSender{
		baseSender: baseSender{
			tokens: make(map[string]string),
			files:  make(map[string]models.FileMeta),
		},
		webServer: lsutils.NewWebServer(true),
		downloads: make([]DownloadEntry, 0),
	}
}

func (rs *ReverseSender) Init(target *models.DeviceInfo, https bool) error {
	rs.local = target
	rs.session = uuid.NewString()
	rs.https = https

	if https {
		privkeyFile := filepath.Join(os.TempDir(), "server.key.pem")
		certFile := filepath.Join(os.TempDir(), "server.crt")
		cert, err := lsutils.LoadOrGenTLScert(privkeyFile, certFile)
		if err != nil {
			return err
		}
		rs.cert = cert
		rs.local.Fingerprint = utils.SHA256ofCert(cert.Leaf)
	}

	rs.reset()

	return nil
}

func (rs *ReverseSender) predownloadHandler(c *fiber.Ctx) error {
	if rs.pin != "" {
		pin := c.Query("pin")
		if pin != rs.pin {
			return c.SendStatus(401)
		}
	}

	var resp models.PreDownloadResp
	resp.SessionId = rs.session
	resp.Files = rs.files
	resp.Info = rs.local

	return c.JSON(&resp)
}

func (rs *ReverseSender) downloadHandler(c *fiber.Ctx) error {
	sessionId := c.Query("sessionId")
	fileId := c.Query("fileId")

	if sessionId == "" || fileId == "" {
		return c.SendStatus(400)
	}

	if sessionId != rs.session {
		return c.SendStatus(403)
	}

	fileMeta, exist := rs.files[fileId]
	if !exist {
		return c.SendStatus(404)
	}

	err := c.SendFile(fileMeta.FullPath)
	if err != nil {
		slog.Info("Fail to send file", "file", fileMeta.Filename)
		return c.SendStatus(500)
	}
	c.Set(fiber.HeaderContentDisposition, fmt.Sprintf(`attachment; filename="%s"`, fileMeta.Filename))

	slog.Info("File sent", "file", fileMeta.Filename, "recv", c.IP())
	return c.SendStatus(200)
}

func (rs *ReverseSender) Start() error {
	server := rs.webServer
	server.Post(constants.PreDownloadPath, rs.predownloadHandler)
	server.Get(constants.DownloadPath, rs.downloadHandler)
	server.Get("/", func(c *fiber.Ctx) error {
		return c.Render(templates.DownloadListTemp, fiber.Map{
			"Files": rs.downloads,
		})
	})

	ip, err := utils.GetMyIPv4Addr()
	if err != nil {
		return err
	}

	scheme := "http"
	if rs.https {
		scheme = "https"
	}

	slog.Info("Start reverse sending server", "https", rs.https)

	// build downloads list
	for idx := range ip {
		host := net.JoinHostPort(ip[idx].String(), "53317")

		for fileId, fileMeta := range rs.files {
			rs.downloads = append(rs.downloads, DownloadEntry{
				Filename: fileMeta.Filename,
				Url: fmt.Sprintf("%s://%s%s?sessionId=%s&fileId=%s",
					scheme, host, constants.DownloadPath, rs.session, fileId),
			})
		}

		fmt.Fprintf(os.Stdout, "Visit %s://%s to download files\n", scheme, host)
	}

	if rs.https {
		return server.ListenTLSWithCertificate("0.0.0.0:53317", rs.cert)
	}
	return server.Listen("0.0.0.0:53317")
}

func (rs *ReverseSender) Cancel() error {
	slog.Info("Shutdown reverse sending server")
	return rs.webServer.Shutdown()
}
