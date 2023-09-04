//go:build tools

// This is used to import things required by build scripts, to force `go mod` to see them as dependencies

package internal

import (
	_ "github.com/maxbrunsfeld/counterfeiter/v6"
)
