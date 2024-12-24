package send

import (
	"errors"
	"log/slog"
	"os"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	"github.com/spf13/cobra"
)

var (
	ip           string
	file         string
	supportHttps bool
	pin          string
)

var Cmd = &cobra.Command{
	Use:   "send",
	Short: "Send files to localsend instance",
	Long:  "Send files to localsend instance",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ip == "" {
			return errors.New("IP address is required")
		}
		if file == "" {
			return errors.New("File is required")
		}

		slog.Info("Start sending", "file", file)

		devinfo, err := localsend.GetDeviceInfo(ip)
		if err != nil {
			slog.Error("Fail to get device info", "error", err)
			return nil
		}

		sender := localsend.NewFileSender()
		sender.SetPIN(pin)
		sender.Init(&devinfo, supportHttps)

		finfo, err := os.Stat(file)
		if err != nil {
			slog.Error("Fail to get file info", "error", err)
			return nil
		}

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

		err = sender.Start()
		if err != nil {
			slog.Error("Fail to send", "error", err)
			return nil
		}

		slog.Info("Finish", "file", file)
		return nil
	},
}

func init() {
	Cmd.PersistentFlags().StringVar(&ip, "ip", "", "IP address of remote localsend instance")
	Cmd.PersistentFlags().StringVarP(&file, "file", "f", "", "File/Directory to be sent")
	Cmd.PersistentFlags().BoolVar(&supportHttps, "https", true, "Do https")
	Cmd.PersistentFlags().StringVarP(&pin, "pin", "p", "", "PIN code")
}
