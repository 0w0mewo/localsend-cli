package scan

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	"github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var timeout int64

var Cmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan local network for localsend instance",
	Long:  "Scan local network for localsend instance",
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Start Scanning")

		webserver := utils.NewWebServer()
		scanner, err := localsend.NewDiscoverier(models.NewDeviceInfo(utils.GenAlias(), uuid.NewString()), false, webserver)
		if err != nil {
			slog.Error("Fail to create scanner", "error", err)
			return
		}

		var wg sync.WaitGroup
		wg.Go(func() {
			scanner.Listen()
		})
		wg.Go(func() {
			// no need to use HTTPS, we just want others reply the device info to us
			webserver.Listen("0.0.0.0:53317")
		})

		<-time.After(time.Second * time.Duration(timeout))

		slog.Info("Stop Scanning")
		scanner.Shutdown()
		webserver.Shutdown()

		devlist := scanner.GetAllDiscovered()
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
	Cmd.PersistentFlags().Int64VarP(&timeout, "timeout", "t", 4, "scan duration in seconds")
}
