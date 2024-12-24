package scan

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/0w0mewo/localsend-cli/internal/store"
	"github.com/spf13/cobra"
)

var timeout int64

var Cmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan local network for localsend instance",
	Long:  "Scan local network for localsend instance",
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Start Scanning")

		// advertise myself so that all the others advertise themselves
		adv, err := localsend.NewMulticastAdvertiser(models.NewDeviceInfo("localsend-cli", ""), true)
		if err != nil {
			slog.Error("Fail to create advertiser", "error", err)
			return
		}
		scanner, err := localsend.NewMulticastScanner()
		if err != nil {
			slog.Error("Fail to create scanner", "error", err)
			return
		}

		go adv.Start()

		err = scanner.Scan(time.Duration(timeout) * time.Second)
		if err != nil {
			slog.Error("Fail multicast scanning", "error", err)
			return
		}

		slog.Info("Stop Scanning")
		scanner.Stop()
		adv.Stop()

		devlist := store.GetAllDevices()

		if len(devlist) > 0 {
			fmt.Fprintf(os.Stdout, "Found Devices: \n")
			for ip, info := range devlist {
				fmt.Fprintf(os.Stdout, "\tName: %s, Version: %s, Address: %s:%d, Protocol: %s\n",
					info.Alias, info.Version, ip, info.Port, info.Protocol)
			}
		} else {
			fmt.Fprintln(os.Stderr, "No device found")
		}
	},
}

func init() {
	Cmd.PersistentFlags().Int64VarP(&timeout, "timeout", "t", 2, "scan duration in seconds")
}
