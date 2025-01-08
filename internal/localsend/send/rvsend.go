package send

import (
	"fmt"
	"log/slog"
	"net"
	"os"

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

	slog.Info("Start reverse sending server")

	// build downloads list
	for idx := range ip {
		host := net.JoinHostPort(ip[idx].String(), "53317")

		for fileId, fileMeta := range rs.files {
			rs.downloads = append(rs.downloads, DownloadEntry{
				Filename: fileMeta.Filename,
				Url: fmt.Sprintf("http://%s%s?sessionId=%s&fileId=%s",
					host, constants.DownloadPath, rs.session, fileId),
			})
		}

		fmt.Fprintf(os.Stdout, "Vist http://%s to download files\n", host)
	}

	return server.Listen("0.0.0.0:53317")
}

func (rs *ReverseSender) Cancel() error {
	slog.Info("Shutdown reverse sending server")
	return rs.webServer.Shutdown()
}
