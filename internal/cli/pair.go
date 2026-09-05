package cli

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cloptima/cloptima-treehouse/internal/auth"
	"github.com/cloptima/cloptima-treehouse/internal/config"
	"github.com/cloptima/cloptima-treehouse/internal/crypto"
	"github.com/cloptima/cloptima-treehouse/internal/tray"
	"github.com/spf13/cobra"
)

// `treehouse pair` connects a machine with no reachable browser.
//
// `treehouse login` cannot do this and never could: approval redirects to a
// listener on this process's own 127.0.0.1, so a browser on any other device
// resolves that to itself and reaches nothing. That is why the daemon has been
// effectively un-connectable on a server -- a gap that predates encryption.
//
// Here nothing has to reach this machine. It starts the flow, prints a short
// code, and polls; the human approves from whatever device they are holding.
func newPairCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "pair",
		Short: "Connect a headless machine using a short code",
		Long: "Connect this machine to your Cloptima account without a local browser.\n\n" +
			"Prints a short code and a URL. Open the URL on any device you are signed\n" +
			"in on, enter the code, and approve this machine. Use this on servers and\n" +
			"anywhere `treehouse login` cannot open a browser.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			apiGatewayURL := cfg.APIGatewayURL
			if apiGatewayURL == "" {
				apiGatewayURL = defaultAPIGatewayURL
			}
			machineName := resolveMachineName(cfg)

			// Before the flow starts, not after the credential arrives: the
			// token is bound to this identity at mint time, so it has to exist
			// first. Same ordering constraint the browser login has.
			identity, err := crypto.EnsureIn(crypto.KeyringStore(), os.Getenv(crypto.EnvMachineIdentity))
			if err != nil {
				return err
			}

			authorization, err := auth.StartDeviceAuthorization(
				apiGatewayURL, machineName, identity.InstanceID.String())
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			verificationURL := strings.TrimRight(tray.ResolveWebURL(apiGatewayURL), "/") + "/settings/pair"
			fmt.Fprintf(out, "\nConnect %s\n\n", machineName)
			// The QR carries the URL only. Scanning it saves retyping an
			// address on a phone; the code is still read and entered by hand,
			// which is what stops a link from being an approval on its own.
			// Whether anything was drawn decides what the next line may claim.
			// A terminal that cannot render it -- piped output, NO_COLOR, a
			// dumb TERM -- would otherwise be told to scan something that is
			// not there.
			scannable := writeQRCode(out, verificationURL)
			if scannable {
				fmt.Fprintln(out)
			}
			fmt.Fprintf(out, "  1. Open   %s\n", verificationURL)
			if scannable {
				fmt.Fprintf(out, "     (or scan the code above)\n")
			}
			fmt.Fprintf(out, "  2. Enter  %s\n\n", authorization.UserCode)
			fmt.Fprintf(out, "Waiting for approval. Press Ctrl-C to stop.\n")

			// Ctrl-C has to work here, because waiting is this command's
			// normal state -- a user who changes their mind should not have to
			// kill the process.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			token, approvedBy, err := auth.PollDeviceAuthorization(ctx, apiGatewayURL, authorization)
			if err != nil {
				return err
			}
			source, err := auth.SaveAccessTokenWithSource(token)
			if err != nil {
				return err
			}

			// Naming the approver is the one check against someone reading the
			// code off a screen and connecting this machine to their own
			// account instead: from here on its repo names, branches and paths
			// flow to whoever approved, and this line is where that shows.
			if approvedBy != "" {
				fmt.Fprintf(out, "\n✅ %s is connected, approved by %s (token stored in %s).\n",
					machineName, approvedBy, source)
			} else {
				fmt.Fprintf(out, "\n✅ %s is connected (token stored in %s).\n", machineName, source)
			}
			fmt.Fprintf(out, "Next: treehouse add --all ~/work && treehouse run --headless\n")
			return nil
		},
	}
}
