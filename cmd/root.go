package cmd

import (
	"log/slog"
	"os"

	"github.com/0w0mewo/localsend-cli/cmd/recv"
	"github.com/0w0mewo/localsend-cli/cmd/scan"
	"github.com/0w0mewo/localsend-cli/cmd/send"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "localsend",
	Short:   "LocalSend CLI",
	Long:    "LocalSend CLI",
	Version: version,
}

func Execute() {
	rootCmd.SetVersionTemplate("{{ .Version }}\n")

	err := rootCmd.Execute()
	if err != nil {
		slog.Error("Fail to execute", "error", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scan.Cmd)
	rootCmd.AddCommand(recv.Cmd)
	rootCmd.AddCommand(send.Cmd)
}
