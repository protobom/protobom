package writer

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/native"
	drivers "github.com/bom-squad/protobom/pkg/native/serializers"
	"github.com/bom-squad/protobom/pkg/sbom"
)

type Writer struct {
	Indent int
	Format formats.Format
}

var (
	regMtx        sync.RWMutex
	serializers   = make(map[formats.Format]native.Serializer)
	defaultIdent  = 4
	defaultFormat = formats.CDX15JSON
)

func New(opts ...WriterOption) *Writer {
	r := &Writer{
		Indent: defaultIdent,
		Format: defaultFormat,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

func init() {
	regMtx.Lock()
	serializers[formats.CDX10JSON] = drivers.NewCDX("1.0", formats.JSON)
	serializers[formats.CDX11JSON] = drivers.NewCDX("1.1", formats.JSON)
	serializers[formats.CDX12JSON] = drivers.NewCDX("1.2", formats.JSON)
	serializers[formats.CDX13JSON] = drivers.NewCDX("1.3", formats.JSON)
	serializers[formats.CDX14JSON] = drivers.NewCDX("1.4", formats.JSON)
	serializers[formats.CDX15JSON] = drivers.NewCDX("1.5", formats.JSON)
	serializers[formats.SPDX23JSON] = drivers.NewSPDX23()
	regMtx.Unlock()
}

// RegisterSerializer registers a new serializer to handle writing serialized
// SBOMs in a specific format. When registerring a new serializer it replaces
// any other previously defined for the same format.
func RegisterSerializer(format formats.Format, s native.Serializer) {
	regMtx.Lock()
	serializers[format] = s
	regMtx.Unlock()
}

func (w *Writer) getFormatSerializer(format formats.Format) (native.Serializer, error) {
	if _, ok := serializers[format]; ok {
		return serializers[format], nil
	}
	return nil, fmt.Errorf("no serializer registered for %s", format)
}

func (w *Writer) WriteStream(bom *sbom.Document, wr io.WriteCloser) error {
	if bom == nil {
		return fmt.Errorf("unable to write sbom to stream, SBOM is nil")
	}

	serializer, err := w.getFormatSerializer(w.Format)
	if err != nil {
		return fmt.Errorf("getting serializer for format %s: %w", w.Format, err)
	}

	nativeDoc, err := serializer.Serialize(bom, &native.SerializeOptions{})
	if err != nil {
		return fmt.Errorf("serializing SBOM to native format: %w", err)
	}

	if err := serializer.Render(nativeDoc, wr, &native.RenderOptions{
		Indent: w.Indent,
	}); err != nil {
		return fmt.Errorf("writing rendered document to string: %w", err)
	}

	return nil
}

// WriteFile takes an sbom.Document and writes it to the file at path
func (w *Writer) WriteFile(bom *sbom.Document, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return w.WriteStream(bom, f)
}
