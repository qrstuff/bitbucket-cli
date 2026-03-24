package main

import (
	"os"

	"github.com/qrstuff/bitbucket-cli/internal/bktcmd"
)

func main() {
	os.Exit(bktcmd.Main())
}
