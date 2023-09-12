package native

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"io"

	"github.com/bom-squad/protobom/pkg/sbom"
)

//counterfeiter:generate . Serializer
type Serializer interface {
	Serialize(*sbom.Document, *SerializeOptions) (interface{}, error)
	Render(interface{}, io.Writer, *RenderOptions) error
}

type SerializeOptions struct{}

type RenderOptions struct {
	Indent int
}
