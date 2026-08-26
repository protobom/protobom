package writer

import (
	"fmt"
	"maps"
	"slices"

	"github.com/protobom/protobom/pkg/datasink"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/mod"
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

func WithMod(m mod.Mod) WriterOption {
	return func(w *Writer) {
		if w.Options.SerializeOptions.Mods == nil {
			w.Options.SerializeOptions.Mods = map[mod.Mod]struct{}{m: {}}
			return
		}
		w.Options.SerializeOptions.Mods[m] = struct{}{}
	}
}

func WithoutMod(m mod.Mod) WriterOption {
	return func(w *Writer) {
		delete(w.Options.SerializeOptions.Mods, m)
	}
}

func WithListener(l datasink.Listener) WriterOption {
	return func(w *Writer) {
		w.Options.Listeners = append(w.Options.Listeners, l)
	}
}

type Options struct {
	Format           formats.Format
	Listeners        []datasink.Listener
	RenderOptions    *native.RenderOptions
	SerializeOptions *native.SerializeOptions
	StoreOptions     *storage.StoreOptions
	formatOptions    map[string]interface{}
}

// clone returns a copy of the options that shares no mutable state with the
// original: the nested option structs are copied and the maps and slices
// are cloned, so WriterOptions applied to the copy cannot reach the source.
func (o *Options) clone() *Options {
	if o == nil {
		return nil
	}
	c := *o
	if o.RenderOptions != nil {
		ro := *o.RenderOptions
		c.RenderOptions = &ro
	}
	if o.SerializeOptions != nil {
		so := *o.SerializeOptions
		so.Mods = maps.Clone(o.SerializeOptions.Mods)
		c.SerializeOptions = &so
	}
	if o.StoreOptions != nil {
		sto := *o.StoreOptions
		c.StoreOptions = &sto
	}
	c.Listeners = slices.Clone(o.Listeners)
	c.formatOptions = maps.Clone(o.formatOptions)
	return &c
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
