package scan

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	"github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/models"
	"github.com/spf13/cobra"
)

var (
	timeout int64
	legacy  bool
)

var Cmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan local network for localsend instance",
	Long:  "Scan local network for localsend instance",
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Start Scanning")

		scanner, err := localsend.NewDiscoverier(
			models.NewDeviceInfo(utils.GenAlias(), utils.GenFingerprint()),
			false)
		if err != nil {
			slog.Error("Fail to create advertiser", "error", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(timeout))
		defer cancel()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanner.Listen()
		}()

		if legacy {
			slog.Info("Performing legacy HTTP subnet scan")
			wg.Add(1)
			go func() {
				defer wg.Done()
				scanner.ScanSubnet(ctx)
			}()
		}

		<-ctx.Done()
		slog.Info("Stop Scanning")
		scanner.Shutdown()
		wg.Wait()

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
	Cmd.PersistentFlags().BoolVarP(&legacy, "legacy", "l", false, "perform legacy HTTP subnet scan")
}
