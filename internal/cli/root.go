package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

const defaultAPIGatewayURL = "https://api.cloptima.ai"

var version = "dev"

func NewRootCommand() *cobra.Command {
	var noTray bool
	root := &cobra.Command{
		Use:     "treehouse",
		Short:   "Live git worktree/diff overview for treehouse.cloptima.ai",
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon(cmd, noTray)
		},
	}
	root.Flags().BoolVar(&noTray, "no-tray", false, "Run in headless console mode without macOS menu bar tray")
	root.Flags().BoolVar(&noTray, "headless", false, "Alias for --no-tray")
	root.AddCommand(newLoginCommand())
	root.AddCommand(newLogoutCommand())
	root.AddCommand(newPairCommand())
	root.AddCommand(newAddCommand())
	root.AddCommand(newRunCommand())
	root.AddCommand(newVersionCommand())
	return root
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print treehouse CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}
