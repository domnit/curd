// Command curd is the Cookie Ushering Retrieval Daemon: one binary that is
// both the CLI and, as `curd daemon`, the long-lived process.
package main

import (
	"os"

	"github.com/domnit/curd/internal/cli"
)

func main() { os.Exit(cli.Execute()) }
