package writer

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer/options"
	"github.com/onesbom/onesbom/pkg/formats"
	cdx14 "github.com/onesbom/onesbom/pkg/formats/cyclonedx/v14"
	"github.com/sirupsen/logrus"
)

type writerImplementation interface {
	GetFormatSerializer(formats.Format) (Serializer, error)
	SerializeSBOM(options.Options, Serializer, *sbom.Document, io.WriteCloser) error
	OpenFile(string) (*os.File, error)
}

type defaultWriterImplementation struct{}

func (di *defaultWriterImplementation) GetFormatSerializer(format formats.Format) (Serializer, error) {
	switch format {
	case formats.CDX14JSON:
		logrus.Infof("Serializing to %s", formats.CDX14JSON)
		return &SerializerCDX14{}, nil
	default:
		return nil, fmt.Errorf("no serializer supports rendering to %s", format)
	}
}

// SerializeSBOM takes an SBOM in protobuf and a serializer and uses it to render
// the document into the serializer format.
func (di *defaultWriterImplementation) SerializeSBOM(opts options.Options, serializer Serializer, bom *sbom.Document, wr io.WriteCloser) error {
	nativeDoc, err := serializer.Serialize(opts, bom)
	if err != nil {
		return fmt.Errorf("serializing SBOM to native format: %w", err)
	}
	if err := serializer.Render(opts, nativeDoc, wr); err != nil {
		return fmt.Errorf("writing rendered document to string: %w", err)
	}
	return nil
}

func findNodeById(bom *sbom.Document, id string) *sbom.Node {
	for _, n := range bom.Nodes {
		if n.Id == id {
			return n
		}
	}
	return nil
}

// nodeTo14Component converta a node in protobuf to a CycloneDX 1.4 component
func nodeToCDX14Component(n *sbom.Node) *cdx14.Component {
	if n == nil {
		return nil
	}
	c := &cdx14.Component{
		Ref:         n.Id,
		Type:        strings.ToLower(n.PrimaryPurpose),
		Name:        n.Name,
		Version:     n.Version,
		Description: n.Description,
		// Components:  []cdx14.Component{},
	}

	if n.Type == sbom.Node_FILE {
		c.Type = "file"
	}

	if n.Licenses != nil && len(n.Licenses) > 0 {
		c.Licenses = []cdx14.License{}
		for _, l := range n.Licenses {
			c.Licenses = append(c.Licenses, cdx14.License{
				License: struct {
					ID string "json:\"id\"" // TODO optimize
				}{l},
			})
		}
	}

	if n.Hashes != nil && len(n.Hashes) > 0 {
		c.Hashes = []cdx14.Hash{}
		for algo, hash := range n.Hashes {
			c.Hashes = append(c.Hashes, cdx14.Hash{
				Algorithm: algo, // Fix to make it valid
				Content:   hash,
			})
		}
	}

	if n.ExternalReferences != nil {
		for _, er := range n.ExternalReferences {
			if er.Type == "purl" {
				c.Purl = er.Url
				continue
			}

			if c.ExternalReferences == nil {
				c.ExternalReferences = []cdx14.ExternalReference{}
			}

			c.ExternalReferences = append(c.ExternalReferences, cdx14.ExternalReference{
				Type: er.Type,
				URL:  er.Url,
			})
		}
	}

	return c
}

// OpenFile opens the file at path and returns it
func (di *defaultWriterImplementation) OpenFile(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	return f, nil
}
