package native

import (
	"io"

	"github.com/bom-squad/protobom/pkg/reader/options"
	"github.com/bom-squad/protobom/pkg/sbom"
)

type Unserializer interface {
	ParseStream(*options.Options, io.Reader) (*sbom.Document, error)
}
