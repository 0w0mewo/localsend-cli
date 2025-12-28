package send

import (
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"os"
	"path/filepath"

	"github.com/0w0mewo/localsend-cli/internal/crypto"
	"github.com/0w0mewo/localsend-cli/internal/localsend"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/0w0mewo/localsend-cli/internal/webrtc/signaling"
	"github.com/0w0mewo/localsend-cli/internal/webrtc/transfer"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	ip             string
	files          []string
	supportHttps   bool
	pin            string
	useDownloadAPI bool
	useWebRTC      bool
	targetID       string
)

var Cmd = &cobra.Command{
	Use:   "send [files]...",
	Short: "Send files to localsend instance",
	Long:  "Send files to localsend instance",
	RunE: func(cmd *cobra.Command, args []string) error {
		files = append(files, args...)
		if len(files) == 0 {
			return errors.New("File is required")
		}

		// WebRTC mode
		if useWebRTC {
			return sendViaWebRTC()
		}

		// HTTP mode (original)
		if ip == "" && !useDownloadAPI {
			return errors.New("IP address is required")
		}

		var err error

		// only request remote device info when download api is unused
		var devinfo models.DeviceInfo
		if !useDownloadAPI {
			devinfo, err = localsend.GetDeviceInfo(ip, supportHttps)
			if err != nil {
				slog.Error("Fail to get device info", "error", err)
				return nil
			}
		} else {
			devinfo = models.NewDeviceInfo(lsutils.GenAlias(), lsutils.GenFingerprint())
		}

		sender := localsend.NewFileSender(useDownloadAPI)
		sender.SetPIN(pin)
		sender.Init(&devinfo, supportHttps)

		// try to add every file
		for _, file := range files {
			finfo, err := os.Stat(file)
			if err != nil {
				slog.Error("Fail to probe file", "file", file, "error", err)
				continue
			}
			if finfo.IsDir() {
				err = sender.AddDir(file)
				if err != nil {
					slog.Error("Fail to add dir, skipping...", "dir", file, "error", err)
					continue
				}
			} else {
				err = sender.AddFile(file)
				if err != nil {
					slog.Error("Fail to add file, skipping...", "file", file, "error", err)
					continue

				}
			}
			slog.Info("Start sending", "file", file)
		}

		go func() {
			<-utils.WaitForSignal()

			slog.Info("Abort")
			err := sender.Cancel()
			if err != nil {
				slog.Error("Fail to cancel", "error", err)
				return
			}
		}()

		err = sender.Start()
		if err != nil {
			slog.Error("Fail to send", "error", err)
			return nil
		}

		slog.Info("Done")
		return nil
	},
}

func sendViaWebRTC() error {
	if targetID == "" {
		return errors.New("target ID is required for WebRTC mode (use --target)")
	}

	target, err := uuid.Parse(targetID)
	if err != nil {
		return fmt.Errorf("invalid target ID: %w", err)
	}

	// Generate signing key
	key, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Generate token
	token, err := key.GenerateTokenTimestamp()
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	// Connect to signaling server
	info := signaling.ClientInfoWithoutID{
		Alias:       lsutils.GenAlias(),
		Version:     "2.1",
		DeviceModel: "LocalSend-CLI",
		DeviceType:  "headless",
		Token:       token,
	}

	slog.Info("Connecting to WebRTC signaling server")
	client, err := signaling.Connect(signaling.DefaultSignalingServer, info)
	if err != nil {
		return fmt.Errorf("failed to connect to signaling server: %w", err)
	}
	defer client.Close()

	slog.Info("Connected to signaling server", "id", client.ClientID())

	// Prepare file metadata
	var fileMetas []transfer.FileMeta
	for _, file := range files {
		finfo, err := os.Stat(file)
		if err != nil {
			slog.Error("Failed to stat file", "file", file, "error", err)
			continue
		}
		if finfo.IsDir() {
			// Walk directory
			filepath.Walk(file, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				fileMetas = append(fileMetas, makeFileMeta(path, info))
				return nil
			})
		} else {
			fileMetas = append(fileMetas, makeFileMeta(file, finfo))
		}
	}

	if len(fileMetas) == 0 {
		return errors.New("no valid files to send")
	}

	slog.Info("Prepared files", "count", len(fileMetas))
	for _, f := range fileMetas {
		slog.Info("File", "name", f.FileName, "size", f.Size)
	}

	// Create sender
	sender := transfer.NewRTCSender(client, key, pin)

	// Send to target
	slog.Info("Sending offer to target", "target", target)
	if err := sender.Send(target, fileMetas); err != nil {
		sender.Close()
		return fmt.Errorf("failed to initiate transfer: %w", err)
	}

	// Send files
	slog.Info("Sending files...")
	if err := sender.SendFiles(); err != nil {
		sender.Close()
		return fmt.Errorf("failed to send files: %w", err)
	}

	sender.Close()
	slog.Info("Transfer complete")
	return nil
}

func makeFileMeta(path string, info os.FileInfo) transfer.FileMeta {
	fileType := mime.TypeByExtension(filepath.Ext(path))
	if fileType == "" {
		fileType = "application/octet-stream"
	}
	return transfer.FileMeta{
		ID:       uuid.New().String(),
		FileName: info.Name(),
		FilePath: path,
		Size:     info.Size(),
		FileType: fileType,
		Modified: info.ModTime(),
	}
}

func init() {
	Cmd.PersistentFlags().StringVar(&ip, "ip", "", "IP address of remote localsend instance")
	Cmd.PersistentFlags().StringSliceVarP(&files, "file", "f", []string{}, "File/Directory to be sent")
	Cmd.PersistentFlags().BoolVar(&supportHttps, "https", true, "Do https")
	Cmd.PersistentFlags().BoolVar(&useDownloadAPI, "dapi", false, "Use Download API(Reverse File Transfer)")
	Cmd.PersistentFlags().StringVarP(&pin, "pin", "p", "", "PIN code")
	Cmd.PersistentFlags().BoolVarP(&useWebRTC, "webrtc", "w", false, "Send via WebRTC signaling server")
	Cmd.PersistentFlags().StringVarP(&targetID, "target", "t", "", "Target peer ID (from scan --webrtc)")
}
