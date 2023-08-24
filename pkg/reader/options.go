package reader

import "github.com/bom-squad/protobom/pkg/unserializer"

type ReaderOption func(*Reader)

func WithCDXUnserializer(u unserializer.CDXUnserializer) ReaderOption {
	return func(r *Reader) {
		r.cdx = u
	}
}

func WithSPDX23Unserializer(u unserializer.SPDX23Unserializer) ReaderOption {
	return func(r *Reader) {
		r.spdx23 = u
	}
}

func WithEncoding(e string) ReaderOption {
	return func(r *Reader) {
		r.encoding = e
	}
}
