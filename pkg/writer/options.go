package writer

import (
	"fmt"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/storage"
)

type WriterOption func(*Writer)

func WithRenderOptions(ro *native.RenderOptions) WriterOption {
	return func(w *Writer) {
		if ro != nil {
			w.Options.RenderOptions = ro
		}
	}
}

func WithSerializeOptions(so *native.SerializeOptions) WriterOption {
	return func(w *Writer) {
		if so != nil {
			w.Options.SerializeOptions = so
		}
	}
}

func WithFormatOptions(driverKey string, opts interface{}) WriterOption {
	return func(w *Writer) {
		w.Options.SetFormatOptions(driverKey, opts)
	}
}

func WithFormat(f formats.Format) WriterOption {
	return func(w *Writer) {
		w.Options.Format = f
	}
}

func WithStoreRetriever(sb storage.StoreRetriever) WriterOption {
	return func(w *Writer) {
		if sb != nil {
			w.Storage = sb
		}
	}
}

func WithStoreOptions(ro *storage.StoreOptions) WriterOption {
	return func(w *Writer) {
		if ro != nil {
			w.Options.StoreOptions = ro
		}
	}
}

type Options struct {
	Format           formats.Format
	RenderOptions    *native.RenderOptions
	SerializeOptions *native.SerializeOptions
	StoreOptions     *storage.StoreOptions
	formatOptions    map[string]interface{}
}

// argToOptsKeyVal returns a key value to access the options dictionary by using
// key as a string or its type if its a serializer driver.
func argToOptsKeyVal(key interface{}) string {
	keyVal, ok := key.(string)
	if !ok {
		keyVal = fmt.Sprintf("%T", key)
	}

	return keyVal
}

func (o *Options) GetFormatOptions(key interface{}) interface{} {
	keyVal := argToOptsKeyVal(key)
	if _, ok := o.formatOptions[keyVal]; ok {
		return o.formatOptions[keyVal]
	}
	// TODO(puerco): create new options struct for serializer
	return nil
}

func (o *Options) SetFormatOptions(key, opts interface{}) {
	if o.formatOptions == nil {
		o.formatOptions = map[string]interface{}{}
	}
	keyVal := argToOptsKeyVal(key)
	if keyVal == "" {
		return
	}
	o.formatOptions[keyVal] = opts
}
