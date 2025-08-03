package send

import (
	"errors"
	"log/slog"
	"os"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	ip             string
	files          []string
	supportHttps   bool
	pin            string
	useDownloadAPI bool
)

var Cmd = &cobra.Command{
	Use:   "send [files]...",
	Short: "Send files to localsend instance",
	Long:  "Send files to localsend instance",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ip == "" && !useDownloadAPI {
			return errors.New("IP address is required")
		}
		files = append(files, args...)
		if len(files) == 0 {
			return errors.New("File is required")
		}

		var err error

		// only request remote device info when download api is unused
		var devinfo models.DeviceInfo
		if !useDownloadAPI {
			devinfo, err = localsend.GetDeviceInfo(ip)
			if err != nil {
				slog.Error("Fail to get device info", "error", err)
				return nil
			}
		} else {
			devinfo = models.NewDeviceInfo(lsutils.GenAlias(), uuid.NewString())
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

func init() {
	Cmd.PersistentFlags().StringVar(&ip, "ip", "", "IP address of remote localsend instance")
	Cmd.PersistentFlags().StringSliceVarP(&files, "file", "f", []string{}, "File/Directory to be sent")
	Cmd.PersistentFlags().BoolVar(&supportHttps, "https", true, "Do https")
	Cmd.PersistentFlags().BoolVar(&useDownloadAPI, "dapi", false, "Use Download API(Reverse File Transfer)")
	Cmd.PersistentFlags().StringVarP(&pin, "pin", "p", "", "PIN code")
}
