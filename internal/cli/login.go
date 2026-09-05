package cli

import (
	"fmt"
	"os"

	"github.com/cloptima/cloptima-treehouse/internal/auth"
	"github.com/cloptima/cloptima-treehouse/internal/config"
	"github.com/cloptima/cloptima-treehouse/internal/crypto"
	"github.com/cloptima/cloptima-treehouse/internal/tray"
	"github.com/spf13/cobra"
)

// Browser login is the only way in, deliberately. A daemon token is useless
// unless it is bound to this machine's instance id at mint time -- the server
// refuses every ingest from an unbound token -- and only the approval page can
// mint one. Pasting a token from the console would store a credential that
// authenticates fine and then fails every push, which is a worse failure than
// having no token at all, so the paste paths are gone rather than offered.
//
// Approval comes back to a listener this process opened on its own 127.0.0.1,
// so a browser anywhere else redirects to its own loopback and reaches
// nothing. The printed URL is therefore a fallback for a browser on *this*
// machine that the OS opener failed to launch, not a way to approve from
// another device.
//
// Headless hosts use `treehouse pair` instead, which is the device
// authorization flow and needs no browser here at all.
func newLoginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate treehouse with your Cloptima account",
		Long: "Authenticate treehouse with your Cloptima account via browser OAuth2.\n\n" +
			"This opens your browser to log in with Google, GitHub, or Email, and\n" +
			"automatically transfers the credential to your daemon. The token is bound\n" +
			"to this machine when it is minted, so it can only be issued this way.\n\n" +
			"On a machine with no browser, use `treehouse pair`.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			webURL := tray.ResolveWebURL(cfg.APIGatewayURL)
			// Same machine name the daemon registers under, so the approval
			// prompt names a machine the user recognises.
			machineName := resolveMachineName(cfg)
			// Generated before the login, not after: the minted token is bound
			// to this identity, and a token minted without it cannot ingest at
			// all.
			identity, err := crypto.EnsureIn(crypto.KeyringStore(), os.Getenv(crypto.EnvMachineIdentity))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Opening browser to authorize %s...\n", machineName)
			if _, err := auth.Login(webURL, machineName, identity.InstanceID.String(), cmd.OutOrStdout()); err != nil {
				return fmt.Errorf(
					"browser login failed: %w; open the URL above in a browser on this machine, "+
						"or run `treehouse pair` if this host has no browser", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "✅ Successfully authenticated with Treehouse!")
			return nil
		},
	}
}

func newLogoutCommand() *cobra.Command {
	var resetMachine bool
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Delete the stored token from the keychain",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := auth.DeleteAccessToken(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "token removed")
			if !resetMachine {
				return nil
			}
			// Separate from the token on purpose, and only ever on an explicit
			// flag: clearing this makes the next login enroll a brand-new
			// machine, orphaning this host's registration and every grant
			// already issued for it. Ordinary logout/login must not do that.
			if err := crypto.ResetIn(crypto.KeyringStore()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(),
				"machine identity removed; the next login enrolls this host as a new machine")
			return nil
		},
	}
	cmd.Flags().BoolVar(&resetMachine, "reset-machine", false,
		"Also delete this machine's identity and content keys, so the next login enrolls a new machine")
	return cmd
}
