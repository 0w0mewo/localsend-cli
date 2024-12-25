package send

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type ReverseSender struct {
	pin       string
	local     *models.DeviceInfo
	webServer *fiber.App
	tokens    map[string]string
	files     map[string]models.FileMeta
	session   string
}

func NewReverseSender() *ReverseSender {
	return &ReverseSender{
		webServer: fiber.New(fiber.Config{
			Prefork:               false,
			DisableStartupMessage: true,
			BodyLimit:             100 * 1024 * 1024 * 1024, // 100G
		}),
		tokens: make(map[string]string),
		files:  make(map[string]models.FileMeta),
	}
}

func (rs *ReverseSender) SetPIN(pin string) {
	rs.pin = pin
}

func (rs *ReverseSender) Init(target *models.DeviceInfo, https bool) error {
	rs.local = target
	rs.session = uuid.NewString()

	for k := range rs.tokens {
		delete(rs.tokens, k)
	}

	for k := range rs.files {
		delete(rs.files, k)
	}

	return nil
}

func (rs *ReverseSender) AddFile(filePath string) error {
	if rs.files == nil {
		rs.files = make(map[string]models.FileMeta)
	}

	fileMeta, err := models.GenFileMeta(filePath)
	if err != nil {
		return err
	}

	rs.files[fileMeta.Id] = fileMeta
	return nil
}

func (rs *ReverseSender) AddDir(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		return rs.AddFile(path)
	})
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

	ip, err := utils.GetMyIPv4Addr()
	if err != nil {
		return err
	}

	slog.Info("Start reverse sending server")

	for idx := range ip {
		for fileId := range rs.files {
			host := net.JoinHostPort(ip[idx].String(), "53317")
			fmt.Fprintf(os.Stdout, "Visit url to fetch file: http://%s%s?sessionId=%s&fileId=%s\n",
				host, constants.DownloadPath, rs.session, fileId)
		}
	}
	return server.Listen("0.0.0.0:53317")
}

func (rs *ReverseSender) Cancel() error {
	slog.Info("Shutdown reverse sending server")
	return rs.webServer.Shutdown()
}
