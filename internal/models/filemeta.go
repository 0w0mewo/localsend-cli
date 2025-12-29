package models

import (
	"mime"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/google/uuid"
)

// FileMetadata contains optional file timestamp information
type FileMetadata struct {
	Modified string `json:"modified,omitempty"`
	Accessed string `json:"accessed,omitempty"`
}

// getAccessTime extracts the access time from FileInfo
// Falls back to modification time if access time cannot be retrieved
func getAccessTime(fi os.FileInfo) time.Time {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		// Platform-specific access time extraction
		// On macOS/BSD: Atimespec
		// On Linux: Atim
		return time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
	}
	// Fallback to modification time
	return fi.ModTime()
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
			Accessed: getAccessTime(fd).Format(time.RFC3339),
		},
		FullPath: fpath,
	}, nil
}
