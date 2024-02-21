package native

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"io"

	"github.com/bom-squad/protobom/pkg/sbom"
)

// type CDXRootScheme func(ctx context.Context, bom *sbom.Document, rootsComp []cdx.Component) (*cdx.Component, []cdx.Component, []cdx.Dependency, error)

//counterfeiter:generate . Serializer
type Serializer interface {
	Serialize(*sbom.Document, *SerializeOptions, interface{}) (interface{}, error)
	Render(interface{}, io.Writer, *RenderOptions, interface{}) error
}

type RenderOptions struct {
	Indent int
}

type SerializeOptions struct {
	// CDXRootSelect serializers.CDXRootScheme
}
