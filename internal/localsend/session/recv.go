package session

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	lserrors "github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/google/uuid"
)

type RecvSession struct {
	saveToDir  string
	fileMetas  *sync.Map
	id         string
	RemoteIP   string
	locked     bool
	valid      bool
	filesCount int64
}

func NewRecvSession(saveToDir string, sessionId string) (*RecvSession, error) {
	sess := &RecvSession{
		saveToDir: saveToDir,
		fileMetas: &sync.Map{},
		locked:    false,
		valid:     true,
		id:        sessionId,
	}

	// ensure saved dir exists
	err := os.MkdirAll(sess.saveToDir, fs.ModePerm)
	if err != nil {
		return nil, err
	}

	return sess, nil
}

func (sess *RecvSession) AddFileMeta(fileId string, fileMeta models.FileMeta) error {
	if sess.locked {
		return lserrors.ErrBlockedByOthers
	}

	// unlikely, but check it anyway
	if fileId != fileMeta.Id {
		return lserrors.ErrUnknown
	}

	// generate token and store the file metadata
	fileMeta.Token = uuid.NewString()
	sess.fileMetas.Store(fileId, fileMeta)

	// increment files count
	atomic.AddInt64(&sess.filesCount, 1)

	return nil
}

func (sess *RecvSession) GenPreUploadResp() *models.PreUploadResp {
	resp := models.NewPreUploadResp(sess.id)

	sess.fileMetas.Range(func(key, value any) bool {
		filedId := key.(string)
		fileMeta := value.(models.FileMeta)
		resp.AddFile(filedId, fileMeta.Token)

		return true
	})

	return resp
}

func (sess *RecvSession) Start() {
	// reject upload request for this session
	sess.locked = true
	sess.valid = true
}

func (sess *RecvSession) SaveFile(fileId string, token string, fileData []byte) error {
	if sess.id == "" || fileId == "" || token == "" {
		return lserrors.ErrInvalidBody
	}

	if !sess.valid {
		return lserrors.ErrRejected
	}

	// validate stored file token with the given one
	v, exist := sess.fileMetas.Load(fileId)
	meta, ok := v.(models.FileMeta)
	if !ok {
		return lserrors.ErrUnknown // unlikely, but check it anyway
	}
	if !exist || meta.Token != token {
		return lserrors.ErrRejected
	}

	// write the file data to disk
	saveAs := filepath.Join(sess.saveToDir, meta.Filename)
	err := os.WriteFile(saveAs, fileData, 0o640)
	if err != nil {
		return lserrors.ErrFileIO
	}

	// calculate checksum if it's provided
	if meta.Checksum != "" {
		checksum, err := utils.SHA256ofFile(saveAs)
		if err != nil {
			return lserrors.ErrChecksum
		}

		if checksum != meta.Checksum {
			return lserrors.ErrChecksum
		}
	}

	slog.Info("Recv file", "file", meta.Filename, "session", sess.id)

	// remove finished file info
	sess.fileMetas.Delete(fileId)
	atomic.AddInt64(&sess.filesCount, -1)

	// end this session if it is the last file it received
	if count := atomic.LoadInt64(&sess.filesCount); count == 0 {
		sess.End()
	}

	return nil
}

func (sess *RecvSession) End() {
	if sess.locked && sess.valid { // make sure it ends once
		sess.locked = false
		sess.valid = false
		sess.fileMetas.Clear()

		slog.Info("Session done", "session", sess.id)
	}
}

func (sess *RecvSession) Finished() bool {
	return (!sess.locked) && (!sess.valid)
}
