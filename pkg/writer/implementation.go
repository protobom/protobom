package writer

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer/options"
)

var (
	regMtx      sync.RWMutex
	serializers = make(map[formats.Format]Serializer)
)

func init() {
	regMtx.Lock()
	serializers[formats.CDX14JSON] = &SerializerCDX14{}
	serializers[formats.SPDX23JSON] = &SerializerSPDX23{}
	regMtx.Unlock()
}

// RegisterSerializer registers a new serializer to handle writing serialized
// SBOMs in a specific format. When registerring a new serializer it replaces
// any other previously defined for the same format.
func RegisterSerializer(format formats.Format, s Serializer) {
	regMtx.Lock()
	serializers[format] = s
	regMtx.Unlock()
}

type writerImplementation interface {
	GetFormatSerializer(formats.Format) (Serializer, error)
	SerializeSBOM(options.Options, Serializer, *sbom.Document, io.WriteCloser) error
	OpenFile(string) (*os.File, error)
}

type defaultWriterImplementation struct{}

func (di *defaultWriterImplementation) GetFormatSerializer(formatOpt formats.Format) (Serializer, error) {
	if _, ok := serializers[formatOpt]; ok {
		return serializers[formatOpt], nil
	}
	return nil, fmt.Errorf("no serializer registered for %s", formatOpt)
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

// OpenFile opens the file at path and returns it
func (di *defaultWriterImplementation) OpenFile(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	return f, nil
}
