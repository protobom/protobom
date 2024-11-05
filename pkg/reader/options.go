package reader

import (
	"fmt"

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
