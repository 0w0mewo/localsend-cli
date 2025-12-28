package models

import (
	"mime"
	"os"
	"path/filepath"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/google/uuid"
)

// FileMetadata contains optional file timestamp information
type FileMetadata struct {
	Modified string `json:"modified,omitempty"`
	Accessed string `json:"accessed,omitempty"`
}

type FileMeta struct {
	Id       string        `json:"id"`
	Filename string        `json:"fileName"`
	Size     int64         `json:"size"`
	FileMIME string        `json:"fileType"`
	Checksum string        `json:"sha256,omitempty"`
	Preview  string        `json:"preview,omitempty"`
	Metadata *FileMetadata `json:"metadata,omitempty"`
	FullPath string        `json:"-"`
}

func GenFileMeta(fpath string) (FileMeta, error) {
	fd, err := os.Stat(fpath)
	if err != nil {
		return FileMeta{}, err
	}

	checksum, err := utils.SHA256ofFile(fpath)
	if err != nil {
		return FileMeta{}, err
	}

	fileType := mime.TypeByExtension(filepath.Ext(fpath))
	if fileType == "" {
		fileType = "text/plain"
	}

	return FileMeta{
		Id:       uuid.NewString(),
		Filename: fd.Name(),
		Size:     fd.Size(),
		FileMIME: fileType,
		Checksum: checksum,
		Metadata: &FileMetadata{
			Modified: fd.ModTime().Format(time.RFC3339),
		},
		FullPath: fpath,
	}, nil
}
