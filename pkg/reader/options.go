package reader

import (
	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/native"
)

type ReaderOption func(*Reader)

func WithUnserializeOptions(uo map[string]*native.UnserializeOptions) ReaderOption {
	return func(w *Reader) {
		if uo != nil {
			w.UnserializeOptions = uo
		}
	}
}

func WithSniffer(s Sniffer) ReaderOption {
	return func(w *Reader) {
		if s != nil {
			w.sniffer = s
		}
	}
}

type Options struct {
	Format             formats.Format
	UnserializeOptions *native.UnserializeOptions
}
