package writer

import (
	"github.com/bom-squad/protobom/pkg/formats"
)

type WriterOption func(*Writer)

func WithFormat(f formats.Format) WriterOption {
	return func(w *Writer) {
		w.Format = f
	}
}

func WithIndent(i int) WriterOption {
	return func(w *Writer) {
		w.Indent = i
	}
}

type Options struct {
	Format formats.Format `yaml:"format,omitempty" json:"format,omitempty"`
	Indent int            `yaml:"indent,omitempty" json:"indent,omitempty"`
}
