package writer

import (
	"io"

	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer/options"
)

type Serializer interface {
	Serialize(options.Options, *sbom.Document) (interface{}, error)
	Render(options.Options, interface{}, io.Writer) error
}
