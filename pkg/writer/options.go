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

// WithFormatOptions sets the options handed to the serializer of a format.
//
// The key names the serializer the options are for, in one of two ways:
//
//   - The Go type of the serializer driver as fmt's %T prints it, for example
//     "*serializers.SPDX3" or "*serializers.CDX". It applies to every format that
//     driver writes.
//   - The format itself, for example string(formats.SPDX3JSON), which is
//     "text/spdx+json;version=3.0.1". It applies to that format only.
//
// When options are set under both keys, those keyed by the format win, as
// the more specific of the two. The options passed to a single call are
// looked up before the writer's own, so a call's options under either key
// win over the writer's. The options must be of the type the driver expects,
// such as serializers.SPDX3Options for the SPDX 3 serializer; options under
// a key that matches no serializer are ignored, and options of another type
// make the built-in serializers return an error.
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

// SetFormatOptions stores the options for a serializer. The key is either a
// string, naming the driver type as %T prints it (for example
// "*serializers.SPDX3") or a format (for example string(formats.SPDX3JSON)), or
// the driver itself, whose type is then used. See WithFormatOptions.
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
