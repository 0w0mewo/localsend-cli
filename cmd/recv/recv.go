package recv

import (
	"log/slog"
	"sync"

	lsrecv "github.com/0w0mewo/localsend-cli/internal/localsend/recv"
	lsutils "github.com/0w0mewo/localsend-cli/internal/localsend/utils"
	"github.com/0w0mewo/localsend-cli/internal/utils"
	"github.com/spf13/cobra"
)

var (
	devname      string
	savetodir    string
	supportHttps bool
	pin          string
)

var Cmd = &cobra.Command{
	Use:   "recv",
	Short: "Receive files from localsend instance",
	Long:  "Receive files from localsend instance",
	Run: func(cmd *cobra.Command, args []string) {
		recver := lsrecv.NewFileReceiver(devname, savetodir, supportHttps)
		recver.SetPIN(pin)
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
	Cmd.PersistentFlags().StringVarP(&devname, "devname", "n", lsutils.GenAlias(), "Device name that is advertising")
	Cmd.PersistentFlags().StringVarP(&savetodir, "dir", "d", ".", "Directory for received files")
	Cmd.PersistentFlags().StringVarP(&pin, "pin", "p", "", "PIN code")
	Cmd.PersistentFlags().BoolVar(&supportHttps, "https", true, "Do https")
}
