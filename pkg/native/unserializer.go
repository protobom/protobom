package native

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"io"

	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/sbom"
)

//counterfeiter:generate . Unserializer
type Unserializer interface {
	Unserialize(io.Reader, *UnserializeOptions, interface{}) (*sbom.Document, error)
}

type UnserializeOptions struct {
	// TrackSource will cause the reader to capture information about the
	// original SBOM document such as its hashes, size and original location.
	TrackSource bool
	Mods        map[mod.Mod]struct{}
}

// IsModEnabled returns true when the passed mod is enabled in the options set.
func (uo *UnserializeOptions) IsModEnabled(m mod.Mod) bool {
	_, ok := uo.Mods[m]
	return ok
}
