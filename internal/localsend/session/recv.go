package session

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	lserrors "github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/google/uuid"
)

type RecvSession struct {
	// filesCount must be first for 64-bit alignment on 32-bit ARM
	filesCount int64
	fileMetas  models.FileMetas
	fileTokens models.FileTokens
	mu         sync.RWMutex
	id         string
	started    atomic.Bool
}

func NewRecvSession(sessionId string) (*RecvSession, error) {
	sess := &RecvSession{
		fileMetas:  make(models.FileMetas),
		fileTokens: make(models.FileTokens),
		id:         sessionId,
	}

	return sess, nil
}

func (sess *RecvSession) AcceptFile(fileId string, fileMeta models.FileMeta) error {
	// reject upload request for a started session
	if sess.started.Load() {
		return lserrors.ErrBlockedByOthers
	}

	// unlikely, but check it anyway
	if fileId != fileMeta.Id {
		return lserrors.ErrUnknown
	}

	sess.mu.Lock()
	// store the file metadata
	sess.fileMetas[fileId] = fileMeta

	// generate file token
	sess.fileTokens[fileId] = uuid.NewString()
	sess.mu.Unlock()

	// increment files count
	atomic.AddInt64(&sess.filesCount, 1)

	return nil
}

func (sess *RecvSession) Start() {
	sess.started.Store(true)
}

func (sess *RecvSession) SaveFile(saveToDir string, fileId string, token string, fileData io.Reader) error {
	if sess.id == "" || fileId == "" || token == "" {
		return lserrors.ErrInvalidBody
	}

	// if a session is not started, it means the session is invalid
	if !sess.started.Load() {
		return lserrors.ErrRejected
	}

	sess.mu.RLock()
	expectedMeta, metaExist := sess.fileMetas[fileId]
	expectedToken, tokenExist := sess.fileTokens[fileId]
	sess.mu.RUnlock()

	// validate
	if !metaExist || !tokenExist || expectedToken != token {
		return lserrors.ErrRejected
	}

	// write the file data to disk while calculating checksum simultaneously
	saveAs := filepath.Join(saveToDir, expectedMeta.Filename)
	hasher := sha256.New()
	file, err := os.Create(saveAs)
	if err != nil {
		return lserrors.ErrFileIO
	}
	defer file.Close()

	writer := io.MultiWriter(file, hasher)
	_, err = io.Copy(writer, fileData)
	if err != nil {
		return lserrors.ErrFileIO
	}

	// calculate checksum if it's provided
	if expectedMeta.Checksum != "" {
		checksum := hex.EncodeToString(hasher.Sum(nil))

		if checksum != expectedMeta.Checksum {
			return lserrors.ErrChecksum
		}
	}

	slog.Info("Recv file", "file", expectedMeta.Filename, "session", sess.id)

	// remove finished file
	atomic.AddInt64(&sess.filesCount, -1)

	// end this session if it is the last file it received
	if count := atomic.LoadInt64(&sess.filesCount); count == 0 {
		sess.End()
	}

	return nil
}

func (sess *RecvSession) FileTokens() models.FileTokens {
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	return sess.fileTokens
}

func (sess *RecvSession) GetFileMeta(fileId string) (models.FileMeta, bool) {
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	meta, ok := sess.fileMetas[fileId]
	return meta, ok
}

func (sess *RecvSession) End() {
	if sess.started.Load() { // make sure it ends once
		sess.started.Store(false)
		atomic.StoreInt64(&sess.filesCount, 0)

		slog.Info("Session done", "session", sess.id)
	}
}

func (sess *RecvSession) Stopped() bool {
	fileLefts := atomic.LoadInt64(&sess.filesCount)

	return (!sess.started.Load()) || (fileLefts == 0)
}
