package native

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"context"
	"io"

	"github.com/bom-squad/protobom/pkg/sbom"
)

// SelectRootsScheme Allows you to modify the Document Root
type SelectRootsScheme func(ctx context.Context, bom *sbom.Document) ([]string, error)

//counterfeiter:generate . Serializer
type Serializer interface {
	Serialize(*sbom.Document, *SerializeOptions, interface{}) (interface{}, error)
	Render(interface{}, io.Writer, *RenderOptions, interface{}) error
}

type RenderOptions struct {
	Indent int
}

type SerializeOptions struct {
	SelectRoots SelectRootsScheme
}
