package writer

import (
	"io"

	"github.com/bom-squad/protobom/pkg/sbom"
)

// SerializerCDX14 is an object that writes a protobuf sbom to CycloneDX 1.4
type SerializerCDX14 struct{}

func (s *SerializerCDX14) Render(*sbom.Document, io.Writer) error {
	return nil

}
