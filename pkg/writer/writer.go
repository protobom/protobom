package writer

import (
	"errors"
	"fmt"
	"io"

	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer/options"
)

type Option func(*Writer)

func New() *Writer {
	return &Writer{
		impl:    &defaultWriterImplementation{},
		Options: options.Default,
	}
}

type Writer struct {
	impl    writerImplementation
	Options options.Options
}

func (w *Writer) WriteStream(bom *sbom.Document, wr io.WriteCloser) error {
	if bom == nil {
		return errors.New("unable to write sbom to stream, SBOM is nil")
	}

	format, err := w.Options.FormatOpt.Select()
	if err != nil {
		return err
	}
	// The target format is in the options ATM. Here we get the
	// serializer for the target we are writing to
	serializer, err := w.impl.GetFormatSerializer(format)
	if err != nil {
		return fmt.Errorf("getting serializer: %w", err)
	}

	if err := w.impl.SerializeSBOM(w.Options, serializer, bom, wr); err != nil {
		return fmt.Errorf("serializing sbom: %w", err)
	}

	return nil
}

func (w *Writer) WriteFile(bom *sbom.Document, path string) error {
	f, err := w.impl.OpenFile(path)
	if err != nil {
		return err
	}

	return w.WriteStream(bom, f)
}
