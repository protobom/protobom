package reader

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

type Options struct {
	Format             formats.Format
	Listeners          []datasink.Listener
	UnserializeOptions *native.UnserializeOptions
	RetrieveOptions    *storage.RetrieveOptions
	formatOptions      map[string]interface{}
}

// clone returns a copy of the options that shares no mutable state with the
// original: the nested option structs are copied and the maps and slices
// are cloned, so ReaderOptions applied to the copy cannot reach the source.
func (o *Options) clone() *Options {
	if o == nil {
		return nil
	}
	c := *o
	if o.UnserializeOptions != nil {
		uo := *o.UnserializeOptions
		uo.Mods = maps.Clone(o.UnserializeOptions.Mods)
		c.UnserializeOptions = &uo
	}
	if o.RetrieveOptions != nil {
		ro := *o.RetrieveOptions
		c.RetrieveOptions = &ro
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
	return nil
}

// SetFormatOptions stores the options for an unserializer. The key is either a
// string, naming the driver type as %T prints it (for example
// "*unserializers.SPDX3") or a format (for example string(formats.SPDX3JSON)), or
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

type ReaderOption func(*Reader)

// WithFormatOptions sets the options handed to the unserializer of a format.
//
// The key names the unserializer the options are for, in one of two ways:
//
//   - The Go type of the unserializer driver as fmt's %T prints it, for example
//     "*unserializers.SPDX3" or "*unserializers.CDX". It applies to every format that
//     driver reads.
//   - The format itself, for example string(formats.SPDX3JSON), which is
//     "text/spdx+json;version=3.0.1". It applies to that format only.
//
// When options are set under both keys, those keyed by the format win, as
// the more specific of the two. The options passed to a single call are
// looked up before the reader's own, so a call's options under either key
// win over the reader's. Options under a key that matches no unserializer
// are ignored. None of the built-in unserializers take options today; a
// custom one decides itself what to do with options of a type it does not
// expect.
func WithFormatOptions(driverKey string, opts interface{}) ReaderOption {
	return func(r *Reader) {
		r.Options.SetFormatOptions(driverKey, opts)
	}
}

func WithUnserializeOptions(uo *native.UnserializeOptions) ReaderOption {
	return func(r *Reader) {
		if uo != nil {
			r.Options.UnserializeOptions = uo
		}
	}
}

func WithSniffer(s Sniffer) ReaderOption {
	return func(r *Reader) {
		if s != nil {
			r.sniffer = s
		}
	}
}

func WithStoreRetriever(sb storage.StoreRetriever) ReaderOption {
	return func(r *Reader) {
		if sb != nil {
			r.Storage = sb
		}
	}
}

func WithRetrieveOptions(ro *storage.RetrieveOptions) ReaderOption {
	return func(r *Reader) {
		if ro != nil {
			r.Options.RetrieveOptions = ro
		}
	}
}

func WithMod(m mod.Mod) ReaderOption {
	return func(r *Reader) {
		if r.Options.UnserializeOptions.Mods == nil {
			r.Options.UnserializeOptions.Mods = map[mod.Mod]struct{}{m: {}}
			return
		}

		r.Options.UnserializeOptions.Mods[m] = struct{}{}
	}
}

func WithoutMod(m mod.Mod) ReaderOption {
	return func(r *Reader) {
		delete(r.Options.UnserializeOptions.Mods, m)
	}
}

func WithListener(l datasink.Listener) ReaderOption {
	return func(r *Reader) {
		r.Options.Listeners = append(r.Options.Listeners, l)
	}
}

func WithTrackSource(t bool) ReaderOption {
	return func(r *Reader) {
		r.Options.UnserializeOptions.TrackSource = t
	}
}
