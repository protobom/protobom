package writer

import (
	"errors"
	"fmt"
	"io"

	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer/options"
)

type Serializer interface {
	Render(*sbom.Document, io.Writer) error
}

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
	s, err := w.impl.GetFormatSerializer(w.Options.Format)
	if err != nil {
		return fmt.Errorf("getting serializer: %w", err)
	}

	if err := w.impl.SerializeSBOM(w.Options, s, bom, wr); err != nil {
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
