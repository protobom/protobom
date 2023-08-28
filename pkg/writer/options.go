package writer

import (
	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/serializer"
)

type WriterOption func(*Writer)

func WithSerializer(s serializer.Serializer) WriterOption {
	return func(w *Writer) {
		w.serializer = s
	}
}

func WithFormat(f formats.Format) WriterOption {
	return func(w *Writer) {
		w.format = f
	}
}

func WithIndent(i int) WriterOption {
	return func(w *Writer) {
		w.ident = i
	}
}

type Options struct {
	Format formats.Format `yaml:"format,omitempty" json:"format,omitempty"`
	Indent int            `yaml:"indent,omitempty" json:"indent,omitempty"`
}
