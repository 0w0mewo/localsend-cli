package recv

import (
	"crypto/tls"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	sess "github.com/0w0mewo/localsend-cli/internal/localsend/session"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/gofiber/fiber/v2"
)

type FileReceiver struct {
	cert         tls.Certificate
	identity     models.DeviceInfo
	webServer    *fiber.App
	supportHttps bool
	sessman      *sess.RecvSessManager
	saveToDir    string
	discoverier  *localsend.Discoverier
	expectedPin  string
}

func NewFileReceiver(devname string, saveToDir string, supportHttps bool) *FileReceiver {
	return &FileReceiver{
		identity:     models.NewDeviceInfo(devname, ""),
		webServer:    lsutils.NewWebServer(),
		supportHttps: supportHttps,
		saveToDir:    saveToDir,
		sessman:      sess.NewRecvSessManager(),
	}
}

func (fr *FileReceiver) SetPIN(pin string) {
	fr.expectedPin = pin
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

		// See https://github.com/localsend/protocol section.2
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
	server.Post(constants.InfoPath, fr.infoHandler)
	server.Get(constants.InfoPathLegacy, fr.infoHandler)

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
