package writer

import (
	"io"

	"github.com/bom-squad/protobom/pkg/writer/options"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// SerializerCDX14 is an object that writes a protobuf sbom to CycloneDX 1.4
type SerializerCDX14 struct {
	SerializerCDX
}

// Render is a wrapper on top of the general CDX serializer
func (s *SerializerCDX14) Render(_ options.Options, doc interface{}, wr io.Writer) error {
	// Call the global CycloneDX serializer method to render the doc
	return s.renderVersion(cdx.SpecVersion1_5, doc, wr)
}
