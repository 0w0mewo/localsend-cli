package recv

import (
	"bytes"
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

	// Filter files by extension if filter is enabled
	if len(fr.allowedExtensions) > 0 {
		filteredFiles := make(models.FileMetas)
		rejectedFiles := []string{}

		for id, fileMeta := range metaReq.Files {
			if fr.IsExtensionAllowed(fileMeta.Filename) {
				filteredFiles[id] = fileMeta
			} else {
				rejectedFiles = append(rejectedFiles, fileMeta.Filename)
			}
		}

		// Log rejected files
		if len(rejectedFiles) > 0 {
			slog.Info("Rejected files due to extension filter", "files", rejectedFiles)
		}

		// If all files were rejected, return an error
		if len(filteredFiles) == 0 {
			slog.Warn("All files rejected by extension filter", "remote", c.IP())
			return c.Status(403).JSON(fiber.Map{
				"error": "No files with allowed extensions",
			})
		}

		// Replace the files with only the allowed ones
		metaReq.Files = filteredFiles
	}

	// new session
	sessionId, err := fr.sessman.NewSession(metaReq.Files)
	if err != nil {
		slog.Error("preupload error", "error", err)
		return c.SendStatus(500)
	}

	slog.Info("Accepting file", "remote", c.IP(), "session", sessionId, "files", len(metaReq.Files))

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
		return c.SendStatus(404)
	}

	// Get file metadata for logging
	fileMeta, _ := session.GetFileMeta(fileId)

	err = session.SaveFile(fr.saveToDir, fileId, token, bytes.NewReader(c.Body()))
	if err != nil {
		slog.Error("Upload error", "remote", c.IP(), "session", sessionId, "error", err)
		return c.SendStatus(500)
	}

	// Log the successful transfer
	fr.LogTransfer(fileMeta.Filename, fileMeta.Size, c.IP())

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