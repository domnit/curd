package cli

import (
	_ "embed"
	"fmt"

	"github.com/spf13/cobra"
)

//go:embed text/guide.txt
var guideText string

func newGuideCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "guide",
		Short: "Print the full mental model of curd (read this first)",
		Long: `Print everything an agent needs to use curd correctly: what it is, policies,
grants and consent, fetch, browser sessions, the explore -> capture -> distill ->
verify -> approve loop, test mode, and troubleshooting by error code.`,
		Args: cobra.NoArgs,
		Run:  func(cmd *cobra.Command, args []string) { fmt.Fprint(cmd.OutOrStdout(), guideText) },
	}
}
