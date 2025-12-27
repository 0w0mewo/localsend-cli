package recv

import (
	"crypto/tls"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	sess "github.com/0w0mewo/localsend-cli/internal/localsend/session"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/gofiber/fiber/v2"
)

type FileReceiver struct {
	cert              tls.Certificate
	identity          models.DeviceInfo
	webServer         *fiber.App
	supportHttps      bool
	sessman           *sess.RecvSessManager
	saveToDir         string
	discoverier       *localsend.Discoverier
	expectedPin       string
	allowedExtensions []string // New field for extension filtering
	transferLogPath   string   // Path to transfer log file
}

// TransferLogEntry represents a single transfer log entry
type TransferLogEntry struct {
	Timestamp string `json:"timestamp"`
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	Sender    string `json:"sender"`
}

func NewFileReceiver(devname string, saveToDir string, supportHttps bool) *FileReceiver {
	return &FileReceiver{
		identity:          models.NewDeviceInfo(devname, ""),
		webServer:         lsutils.NewWebServer(),
		supportHttps:      supportHttps,
		saveToDir:         saveToDir,
		sessman:           sess.NewRecvSessManager(),
		allowedExtensions: nil, // nil means accept all
	}
}

func (fr *FileReceiver) SetPIN(pin string) {
	fr.expectedPin = pin
}

func (fr *FileReceiver) SetTransferLog(path string) {
	fr.transferLogPath = path
}

func (fr *FileReceiver) LogTransfer(filename string, size int64, sender string) {
	if fr.transferLogPath == "" {
		return
	}

	entry := TransferLogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Filename:  filename,
		Size:      size,
		Sender:    sender,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		slog.Error("Failed to marshal transfer log entry", "error", err)
		return
	}

	f, err := os.OpenFile(fr.transferLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		slog.Error("Failed to open transfer log", "error", err)
		return
	}
	defer f.Close()

	f.Write(data)
	f.WriteString("\n")
}

// SetAllowedExtensions sets the list of allowed file extensions. 
// Extensions should be lowercase without the leading dot (e.g., "pdf", "epub").
// If empty or nil, all extensions are accepted.
func (fr *FileReceiver) SetAllowedExtensions(extensions []string) {
	fr.allowedExtensions = extensions
	if len(extensions) > 0 {
		slog.Info("File extension filter enabled", "allowed", extensions)
	}
}

// IsExtensionAllowed checks if a filename has an allowed extension.
// Returns true if no filter is set or if the extension is in the allowed list.
func (fr *FileReceiver) IsExtensionAllowed(filename string) bool {
	// No filter set, accept all
	if len(fr.allowedExtensions) == 0 {
		return true
	}

	// Get the extension (without the dot, lowercase)
	ext := filepath.Ext(filename)
	if ext == "" {
		return false // No extension, reject
	}
	ext = ext[1:] // Remove the leading dot
	ext = strings.ToLower(ext)

	// Check if it's in the allowed list
	for _, allowed := range fr.allowedExtensions {
		if ext == allowed {
			return true
		}
	}

	return false
}

func (fr *FileReceiver) Init() error {
	var err error

	// ensure save directory exists
	err = os.MkdirAll(fr.saveToDir, fs.ModePerm)
	if err != nil {
		return err
	}

	if fr.supportHttps {
		slog.Info("Generating https certificate")

		// load cert for https server
		// TODO: save certificate in user config directory
		privkeyFile := filepath.Join(os.TempDir(), "server.key.pem")
		certFile := filepath.Join(os.TempDir(), "server.crt")
		fr.cert, err = lsutils.LoadOrGenTLScert(privkeyFile, certFile)
		if err != nil {
			return err
		}

		// See https://github.com/localsend/protocol section. 2
		fr.identity.Fingerprint = utils.SHA256ofCert(fr.cert.Leaf)
	}

	// start advertisement
	fr.discoverier, err = localsend.NewDiscoverier(fr.identity, fr.supportHttps)
	if err != nil {
		return err
	}

	return err
}

func (fr *FileReceiver) Start() error {
	server := fr.webServer
	server.Post(constants.PreuploadPath, fr.preUploadHandler)
	server.Post(constants.UploadPath, fr.uploadHandler)
	server.Post(constants.CancelPath, fr.cancelHandler)
	server.Get(constants.InfoPath, fr.infoHandler)
	server.Get(constants.InfoPathV1, fr.infoHandler)
	server.Post(constants.RegisterPath, fr.registerHandler)
	server.Post(constants.RegisterPathV1, fr.registerHandler)
	slog.Info("Waiting for files (Ctrl-C to terminate)")

	go fr.advertise() // let others know we are here

	if fr.supportHttps {
		return fr.webServer.ListenTLSWithCertificate("0.0.0.0:53317", fr.cert)
	}

	return fr.webServer.Listen("0.0.0.0:53317")
}

func (fr *FileReceiver) advertise() error {
	return fr.discoverier.Listen()
}

func (fr *FileReceiver) Stop() error {
	slog.Info("Stop receiving")

	fr.discoverier.Shutdown()
	return fr.webServer.Shutdown()
}