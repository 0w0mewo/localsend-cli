package session

import (
	"log/slog"
	"sync"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/localsend/constants"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/google/uuid"
)

type RecvSessManager struct {
	sessions *sync.Map
}

func NewRecvSessManager() *RecvSessManager {
	return &RecvSessManager{
		sessions: &sync.Map{},
	}
}

func (rsm *RecvSessManager) Start() {
	go rsm.vacuumTask()
}

func (rsm *RecvSessManager) vacuumTask() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		rsm.sessions.Range(func(key, value any) bool {
			sessionId := key.(string)
			session := value.(*RecvSession)

			if session.Stopped() {
				slog.Info("Cleanup stopped session", "session", sessionId)
				rsm.sessions.Delete(sessionId)
			}

			return true
		})
	}
}

func (rsm *RecvSessManager) GeneratePreUploadResp(sessionId string) (models.PreUploadResp, error) {
	sess, err := rsm.GetSession(sessionId)
	if err != nil {
		return models.PreUploadResp{}, err
	}

	var resp models.PreUploadResp
	resp.Tokens = sess.FileTokens()
	resp.SessionId = sessionId

	return resp, nil
}

func (rsm *RecvSessManager) NewSession(reqFiles models.FileMetas) (string, error) {
	sessionId := uuid.NewString()
	session, err := NewRecvSession(sessionId)
	if err != nil {
		return "", err
	}

	// accept every files the client claimed
	for fileId, fileMeta := range reqFiles {
		err = session.AcceptFile(fileId, fileMeta)
		if err != nil {
			return "", err
		}
	}

	// store and start session
	rsm.sessions.Store(sessionId, session)
	session.Start()

	return sessionId, nil
}

func (rsm *RecvSessManager) KillSession(sessionId string) {
	v, exist := rsm.sessions.LoadAndDelete(sessionId)
	session := v.(*RecvSession)
	if !exist || session == nil {
		return
	}
	session.End()
}

func (rsm *RecvSessManager) GetSession(sessionId string) (*RecvSession, error) {
	v, exist := rsm.sessions.Load(sessionId)
	session := v.(*RecvSession)
	if !exist || session == nil {
		return nil, constants.ErrNotFound
	}

	return session, nil
}
