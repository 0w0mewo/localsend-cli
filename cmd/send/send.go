package send

import (
	"errors"
	"log/slog"
	"os"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/spf13/cobra"
)

var (
	ip             string
	file           string
	supportHttps   bool
	pin            string
	useDownloadAPI bool
)

var Cmd = &cobra.Command{
	Use:   "send",
	Short: "Send files to localsend instance",
	Long:  "Send files to localsend instance",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ip == "" && !useDownloadAPI {
			return errors.New("IP address is required")
		}
		if file == "" {
			return errors.New("File is required")
		}
		finfo, err := os.Stat(file)
		if err != nil {
			slog.Error("Fail to get file info", "error", err)
			return nil
		}

		slog.Info("Start sending", "file", file)

		// only request remote device info when download api is unused
		var devinfo models.DeviceInfo
		if !useDownloadAPI {
			devinfo, err = localsend.GetDeviceInfo(ip)
			if err != nil {
				slog.Error("Fail to get device info", "error", err)
				return nil
			}
		} else {
			devinfo = models.NewDeviceInfo("localsend-cli", "")
		}

		sender := localsend.NewFileSender(useDownloadAPI)
		sender.SetPIN(pin)
		sender.Init(&devinfo, supportHttps)

		if finfo.IsDir() {
			err = sender.AddDir(file)
			if err != nil {
				slog.Error("Fail to add dir ", "error", err)
				return nil
			}
		} else {
			err = sender.AddFile(file)
			if err != nil {
				slog.Error("Fail to add file ", "error", err)
				return nil
			}
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

		return nil
	},
}

func init() {
	Cmd.PersistentFlags().StringVar(&ip, "ip", "", "IP address of remote localsend instance")
	Cmd.PersistentFlags().StringVarP(&file, "file", "f", "", "File/Directory to be sent")
	Cmd.PersistentFlags().BoolVar(&supportHttps, "https", true, "Do https")
	Cmd.PersistentFlags().BoolVar(&useDownloadAPI, "dapi", false, "Use Download API(Reverse File Transfer)")
	Cmd.PersistentFlags().StringVarP(&pin, "pin", "p", "", "PIN code")
}
