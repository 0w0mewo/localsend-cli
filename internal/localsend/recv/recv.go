package recv

import (
	"crypto/tls"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	sess "github.com/0w0mewo/localsend-cli/internal/session"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/gofiber/fiber/v2"
	fiberutils "github.com/gofiber/fiber/v2/utils"
	"github.com/google/uuid"
)

type FileReceiver struct {
	cert         tls.Certificate
	identity     models.DeviceInfo
	webServer    *fiber.App
	supportHttps bool
	sessStore    *sync.Map
	saveToDir    string
	discoverier  *localsend.Discoverier
	expectedPin  string
	done         chan struct{}
}

func NewFileReceiver(devname string, saveToDir string, supportHttps bool) *FileReceiver {
	return &FileReceiver{
		identity:     models.NewDeviceInfo(devname, ""),
		webServer:    lsutils.NewWebServer(),
		supportHttps: supportHttps,
		sessStore:    &sync.Map{},
		saveToDir:    saveToDir,
		done:         make(chan struct{}),
	}
}

func (fr *FileReceiver) SetPIN(pin string) {
	fr.expectedPin = pin
}

func (fr *FileReceiver) Init() error {
	var err error

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

func (fr *FileReceiver) preUploadHandler(c *fiber.Ctx) error {
	// check pin if it's set
	if fr.expectedPin != "" {
		pin := c.Query("pin")
		if pin != fr.expectedPin {
			return c.SendStatus(403)
		}
	}

	var metaReq models.PreUploadReq

	err := c.BodyParser(&metaReq)
	if err != nil {
		return c.SendStatus(400)
	}

	// assign session
	sessionId := uuid.NewString()
	session, err := sess.NewRecvSession(fr.saveToDir, sessionId)
	if err != nil {
		slog.Error("preupload error", "error", err)
		return c.SendStatus(500)
	}
	session.RemoteIP = fiberutils.CopyString(c.IP()) // strings in fiber are unsafe due to zero allocation

	// accept every files the client claimed
	for fileId, FileMeta := range metaReq.Files {
		err = session.AddFileMeta(fileId, FileMeta)
		if err != nil {
			return c.SendStatus(409)
		}
	}

	// register session
	fr.sessStore.Store(sessionId, session)
	session.Start()

	slog.Info("Accepting file", "remote", session.RemoteIP, "session", sessionId)

	resp := session.GenPreUploadResp()
	return c.JSON(resp)
}

func (fr *FileReceiver) uploadHandler(c *fiber.Ctx) error {
	sessionId := c.Query("sessionId")
	fileId := c.Query("fileId")
	token := c.Query("token")

	if sessionId == "" || fileId == "" || token == "" {
		return c.SendStatus(400)
	}

	v, exist := fr.sessStore.Load(sessionId)
	session := v.(*sess.RecvSession)
	if session == nil || !exist {
		return c.SendStatus(404)
	}

	err := session.SaveFile(fileId, token, c.Body())
	if err != nil {
		slog.Error("Upload error", "remote", session.RemoteIP, "session", sessionId, "error", err)
		return c.SendStatus(500)
	}

	return c.SendStatus(200)
}

func (fr *FileReceiver) cancelHandler(c *fiber.Ctx) error {
	sessionId := c.Query("sessionId")
	if sessionId == "" {
		return c.SendStatus(400)
	}

	// remove session
	v, exist := fr.sessStore.LoadAndDelete(sessionId)
	sess := v.(*sess.RecvSession)
	if sess == nil || !exist {
		return c.SendStatus(404)
	}
	sess.End()

	return c.SendStatus(200)
}

func (fr *FileReceiver) infoHandler(c *fiber.Ctx) error {
	return c.JSON(&fr.identity)
}

func (fr *FileReceiver) Start() error {
	server := fr.webServer
	server.Post(constants.PreuploadPath, fr.preUploadHandler)
	server.Post(constants.UploadPath, fr.uploadHandler)
	server.Post(constants.CancelPath, fr.cancelHandler)
	server.Get(constants.InfoPath, fr.infoHandler)
	slog.Info("Waitting for receiving files (Ctrl-C to terminate)")

	go fr.gc()
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
	fr.done <- struct{}{}
	return fr.webServer.Shutdown()
}

func (fr *FileReceiver) gc() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fr.done:
			return

		// remove every finished session every 5 seconds
		case <-ticker.C:
			fr.sessStore.Range(func(key, value any) bool {
				sessionId := key.(string)
				session := value.(*sess.RecvSession)

				if session.Finished() {
					session.End()
					fr.sessStore.Delete(sessionId)

					slog.Debug("Remove finished session", "remote", session.RemoteIP, "session", sessionId)
				}

				return true
			})
		}
	}
}
