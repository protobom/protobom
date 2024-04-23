package native

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"io"

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

type SerializeOptions struct{}
