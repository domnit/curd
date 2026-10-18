package cli

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/chrome"
)

func newSetupCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "One-time macOS keychain setup so curd never prompts again",
		Long: `On macOS, Chrome encrypts its cookies with a key stored in the keychain item
"Chrome Safe Storage". By default the daemon asks for it once per start and
macOS shows a keychain dialog. "curd setup" triggers that dialog now so you can
click "Always Allow": the curd binary is then added to the item's access list
and the key is fetched silently from then on.

What happens: curd reads the key once, only to check that access works. The key
is never printed or stored. Afterwards consider setting

  keychain: always-allow

in ~/.config/curd/config.yaml (the key is then fetched on demand rather than at
every start). "strict" never caches the key at all. Because the keychain then
gates nothing, curd's own consent dialogs are the only approval step.

macOS only; elsewhere this command only explains that.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if runtime.GOOS != "darwin" {
				fmt.Fprintf(out, "curd setup is macOS-only (it configures keychain access to Chrome's Safe Storage key); this is %s.\n", runtime.GOOS)
				fmt.Fprintln(out, "Nothing to do here. For development use `curd test-env up`.")
				return nil
			}
			fmt.Fprintln(out, "curd will now read Chrome's \"Chrome Safe Storage\" key from the keychain.")
			fmt.Fprintln(out, "macOS will ask for permission: click \"Always Allow\" to let this curd binary read it silently from now on.")
			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()
			keys, err := chrome.KeychainProvider().Keys(ctx)
			if err != nil {
				return apierr.Newf(apierr.SourceError, "is Chrome installed and have you launched it once? Re-run `curd setup` and click Always Allow when asked",
					"could not read the Chrome Safe Storage key: %v", err)
			}
			for _, k := range keys {
				for i := range k {
					k[i] = 0
				}
			}
			fmt.Fprintln(out, "ok: the keychain key is accessible (it was not printed or saved).")
			fmt.Fprintln(out, "Next: if you clicked Always Allow, add `keychain: always-allow` to ~/.config/curd/config.yaml, then restart the daemon (`curd daemon stop`).")
			return nil
		},
	}
}
