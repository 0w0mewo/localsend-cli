package recv

import (
	"log/slog"
	"sync"

	"github.com/0w0mewo/localsend-cli/internal/localsend"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/spf13/cobra"
)

var (
	devname      string
	savetodir    string
	supportHttps bool
)

var Cmd = &cobra.Command{
	Use:   "recv",
	Short: "Receive files from localsend instance",
	Long:  "Receive files from localsend instance",
	Run: func(cmd *cobra.Command, args []string) {
		recver := localsend.NewFileReceiver(devname, savetodir, supportHttps)
		recver.Init()

		var wg sync.WaitGroup

		// start recv server
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := recver.Start()
			if err != nil {
				slog.Error("Fail to start server", "error", err)
				return
			}
		}()

		<-utils.WaitForSignal()

		recver.Stop()
		wg.Wait()
	},
}

func init() {
	Cmd.PersistentFlags().StringVarP(&devname, "devname", "n", "localsend-cli", "Device name that is advertising")
	Cmd.PersistentFlags().StringVarP(&savetodir, "dir", "d", ".", "Directory for received files")
	Cmd.PersistentFlags().BoolVar(&supportHttps, "https", true, "Do https")
}
