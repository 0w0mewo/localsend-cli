package recv

import (
	"bytes"
	"log/slog"

	"github.com/0w0mewo/localsend-cli/internal/crypto"
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
	savedFilename, err := session.SaveFile(fr.saveToDir, fileId, token, c.IP(), bytes.NewReader(c.Body()))
	if err != nil {
		slog.Error("Upload error", "remote", c.IP(), "session", sessionId, "error", err)
		return c.SendStatus(constants.Status(err))
	}

	// Log the successful transfer with the actual saved filename (may differ from original if renamed)
	fr.LogTransfer(savedFilename, fileMeta.Size, c.IP())

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

// nonceExchangeHandler implements POST /api/localsend/v3/nonce
// This exchanges nonces for secure token verification in v3 protocol.
func (fr *FileReceiver) nonceExchangeHandler(c *fiber.Ctx) error {
	var req models.NonceRequest
	if err := c.BodyParser(&req); err != nil {
		slog.Warn("Invalid nonce request", "error", err, "remote", c.IP())
		return c.SendStatus(400)
	}

	// Decode nonce from base64
	nonce, err := crypto.DecodeNonce(req.Nonce)
	if err != nil {
		slog.Warn("Invalid nonce format", "error", err, "remote", c.IP())
		return c.SendStatus(400)
	}

	// Validate nonce length (16-128 bytes per protocol spec)
	if !crypto.ValidateNonce(nonce) {
		slog.Warn("Invalid nonce length", "length", len(nonce), "remote", c.IP())
		return c.SendStatus(400)
	}

	// Get client identifier (IP for now, could be cert public key for HTTPS)
	clientID := c.IP()

	// Store received nonce from client
	fr.receivedNonceCache.Put(clientID, nonce)

	// Generate new nonce for client
	newNonce, err := crypto.GenerateNonce()
	if err != nil {
		slog.Error("Failed to generate nonce", "error", err)
		return c.SendStatus(500)
	}

	// Store generated nonce for later verification
	fr.generatedNonceCache.Put(clientID, newNonce)

	// Return response with base64-encoded nonce
	resp := models.NonceResponse{
		Nonce: crypto.EncodeNonce(newNonce),
	}

	slog.Info("Nonce exchange successful",
		"remote", clientID,
		"clientNonceLen", len(nonce),
		"serverNonceLen", len(newNonce))

	return c.JSON(&resp)
}

// registerV3Handler implements POST /api/localsend/v3/register
// This handles device registration with v3 protocol fields.
func (fr *FileReceiver) registerV3Handler(c *fiber.Ctx) error {
	var req models.RegisterRequestV3
	if err := c.BodyParser(&req); err != nil {
		slog.Error("Failed to parse v3 register request", "error", err)
		return c.SendStatus(400)
	}

	// Build response from our identity
	resp := models.RegisterResponseV3{
		Alias:           fr.identity.Alias,
		Version:         fr.identity.Version,
		DeviceModel:     fr.identity.DeviceModel,
		DeviceType:      constants.DeviceTypeToV3(fr.identity.DeviceType),
		Token:           fr.identity.Token,
		HasWebInterface: false, // CLI doesn't have web interface
	}

	slog.Info("V3 register received", "remote", c.IP(), "sender", req.Alias)

	return c.JSON(&resp)
}
