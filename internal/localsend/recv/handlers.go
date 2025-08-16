package recv

import (
	"log/slog"

	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/gofiber/fiber/v2"
)

func (fr *FileReceiver) preUploadHandler(c *fiber.Ctx) error {
	// check pin if it's set
	if fr.expectedPin != "" {
		pin := c.Query("pin")
		if pin != fr.expectedPin {
			return c.SendStatus(401)
		}
	}

	var metaReq models.PreUploadReq

	err := c.BodyParser(&metaReq)
	if err != nil {
		return c.SendStatus(400)
	}

	// new session
	sessionId, err := fr.sessman.NewSession(metaReq.Files)
	if err != nil {
		slog.Error("preupload error", "error", err)
		return c.SendStatus(500)
	}

	slog.Info("Accepting file", "remote", c.IP(), "session", sessionId)

	resp, err := fr.sessman.GeneratePreUploadResp(sessionId)
	if err != nil {
		return c.SendStatus(500)
	}

	return c.JSON(&resp)
}

func (fr *FileReceiver) uploadHandler(c *fiber.Ctx) error {
	sessionId := c.Query("sessionId")
	fileId := c.Query("fileId")
	token := c.Query("token")

	if sessionId == "" || fileId == "" || token == "" {
		return c.SendStatus(400)
	}

	session, err := fr.sessman.GetSession(sessionId)
	if err != nil {
		c.SendStatus(404)
	}

	err = session.SaveFile(fr.saveToDir, fileId, token, c.Body())
	if err != nil {
		slog.Error("Upload error", "remote", c.IP(), "session", sessionId, "error", err)
		return c.SendStatus(500)
	}

	return c.SendStatus(200)
}

func (fr *FileReceiver) cancelHandler(c *fiber.Ctx) error {
	sessionId := c.Query("sessionId")
	if sessionId == "" {
		return c.SendStatus(400)
	}

	fr.sessman.KillSession(sessionId)
	return c.SendStatus(200)
}

func (fr *FileReceiver) infoHandler(c *fiber.Ctx) error {
	return c.JSON(&fr.identity)
}
