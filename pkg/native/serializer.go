package native

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"io"

	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/sbom"
)

//counterfeiter:generate . Serializer
type Serializer interface {
	Serialize(*sbom.Document, *SerializeOptions, interface{}) (interface{}, error)
	Render(interface{}, io.Writer, *RenderOptions, interface{}) error
}

type RenderOptions struct {
	Indent int
}

type SerializeOptions struct {
	Mods map[mod.Mod]struct{}
}

// IsModEnabled returns true when the passed mod is enabled in the options set.
func (so *SerializeOptions) IsModEnabled(m mod.Mod) bool {
	_, ok := so.Mods[m]
	return ok
}
