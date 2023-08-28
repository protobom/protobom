package writer

import (
	"fmt"
	"io"
	"os"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/sbom"

	"github.com/bom-squad/protobom/pkg/serializer"
)

type Writer struct {
	serializer serializer.Serializer
	ident      int
	format     formats.Format
}

func New(opts ...WriterOption) *Writer {
	r := &Writer{
		ident:  4,
		format: formats.CDX15JSON, // TODO: should we really default to format? or should we crash if not set?
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.serializer == nil {
		r.serializer = r.createSerializer(r.format)
	}

	return r
}

func (w *Writer) createSerializer(format formats.Format) serializer.Serializer {
	opt := &serializer.Options{
		Encoding: format.Encoding(),
		Version:  format.Version(),
		Indent:   w.ident,
	}

	if format.Type() == formats.CDXFORMAT {
		return serializer.NewCDX(opt)
	}

	if format.Type() == formats.SPDXFORMAT {
		if format.Version() == "2.3" {
			return serializer.NewSPDX23(opt)
		}
	}

	return nil
}

func (w *Writer) WriteStream(bom *sbom.Document, wr io.WriteCloser) error {
	if bom == nil {
		return fmt.Errorf("unable to write sbom to stream, SBOM is nil")
	}

	nativeDoc, err := w.serializer.Serialize(bom)
	if err != nil {
		return fmt.Errorf("serializing SBOM to native format: %w", err)
	}

	if err := w.serializer.Render(nativeDoc, wr); err != nil {
		return fmt.Errorf("writing rendered document to string: %w", err)
	}

	return nil
}

// WriteFile takes an sbom.Document and writes it to the file at path
func (w *Writer) WriteFile(bom *sbom.Document, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening file %s: %w", path, err)
	}

	return w.WriteStream(bom, f)
}
