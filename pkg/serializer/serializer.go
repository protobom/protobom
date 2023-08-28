package serializer

import (
	"io"

	"github.com/bom-squad/protobom/pkg/sbom"
)

type Serializer interface {
	Serialize(*sbom.Document) (interface{}, error)
	Render(interface{}, io.Writer) error
}
