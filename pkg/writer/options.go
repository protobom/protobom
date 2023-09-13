package writer

import (
	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/native"
)

type WriterOption func(*Writer)

func WithRenderOptions(ro map[string]*native.RenderOptions) WriterOption {
	return func(w *Writer) {
		if ro != nil {
			w.RenderOptions = ro
		}
	}
}

func WithSerializeOptions(so map[string]*native.SerializeOptions) WriterOption {
	return func(w *Writer) {
		if so != nil {
			w.SerialzeOptions = so
		}
	}
}

func WithFormat(f formats.Format) WriterOption {
	return func(w *Writer) {
		if f != "" {
			w.Format = f
		}
	}
}

type Options struct {
	Format           formats.Format
	RenderOptions    *native.RenderOptions
	SerializeOptions *native.SerializeOptions
}

type DefaultSerializeOptions struct{}

type Config struct {
	RenderOptions    interface{}
	SerializeOptions interface{}
}
