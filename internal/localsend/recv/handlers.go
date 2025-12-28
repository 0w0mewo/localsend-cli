package recv

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
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

	// Per protocol spec Section 4.1: return 409 when blocked by another session
	if fr.sessman.HasActiveSessions() {
		slog.Info("Blocked upload request - another session is active", "remote", c.IP())
		return c.SendStatus(409)
	}

	var metaReq models.PreUploadReq

	err := c.BodyParser(&metaReq)
	if err != nil {
		return c.SendStatus(400)
	}

	// Per protocol spec Section 4.1: return 204 when no file transfer is needed
	// This happens when all requested files already exist with matching size.
	// Different-sized files with same name will proceed and get counter suffix.
	if fr.allFilesExist(metaReq.Files) {
		slog.Info("All files already exist, no transfer needed", "remote", c.IP())
		return c.SendStatus(204)
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
			return c.SendStatus(403)
		}

		// Replace the files with only the allowed ones
		metaReq.Files = filteredFiles
	}

	// new session - store client IP for validation per protocol spec Section 4.2
	sessionId, err := fr.sessman.NewSession(metaReq.Files, c.IP())
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
		return c.SendStatus(403) // Invalid session = rejected per protocol spec
	}

	// Get file metadata for logging
	fileMeta, _ := session.GetFileMeta(fileId)

	// Pass client IP for validation per protocol spec Section 4.2
	err = session.SaveFile(fr.saveToDir, fileId, token, c.IP(), bytes.NewReader(c.Body()))
	if err != nil {
		slog.Error("Upload error", "remote", c.IP(), "session", sessionId, "error", err)
		return c.SendStatus(constants.Status(err))
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

func (fr *FileReceiver) registerHandler(c *fiber.Ctx) error {
	var announcement models.Announcement
	if err := c.BodyParser(&announcement); err != nil {
		return c.SendStatus(400)
	}

	// Register the discovered device
	announcement.IP = c.IP()
	if fr.discoverier != nil {
		fr.discoverier.RegisterDevice(announcement)
	}

	// Respond with our device info
	return c.JSON(&fr.identity)
}

// allFilesExist checks if all requested files already exist in the save directory
// with matching size. Used to return 204 per protocol spec Section 4.1.
func (fr *FileReceiver) allFilesExist(files models.FileMetas) bool {
	if len(files) == 0 {
		return true // No files to transfer
	}

	for _, fileMeta := range files {
		filePath := filepath.Join(fr.saveToDir, fileMeta.Filename)
		info, err := os.Stat(filePath)
		if err != nil {
			return false // File doesn't exist
		}
		if info.Size() != fileMeta.Size {
			return false // Size mismatch, will get counter suffix
		}
	}
	return true
}
