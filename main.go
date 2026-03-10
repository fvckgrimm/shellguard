package main

import (
	"os"

	"github.com/fvckgrimm/shellguard/cmd/shellguard"
)

func main() {
	if err := shellguard.Execute(); err != nil {
		os.Exit(1)
	}
}
