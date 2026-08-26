package reader

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/storage"
)

// Readers must not share the package defaults: configuring one reader
// must not change the defaults or any other reader.
func TestNewDoesNotShareDefaults(t *testing.T) {
	defaultTrack := defaultOptions.UnserializeOptions.TrackSource
	defaultMods := len(defaultOptions.UnserializeOptions.Mods)
	require.Empty(t, defaultOptions.formatOptions)

	first := New(
		WithTrackSource(!defaultTrack),
		WithMod(mod.Mod("test-mod")),
		WithFormatOptions("driver", "opts"),
		WithRetrieveOptions(&storage.RetrieveOptions{BackendOptions: "be"}),
	)
	second := New()

	// The defaults are untouched
	require.Equal(t, defaultTrack, defaultOptions.UnserializeOptions.TrackSource)
	require.Len(t, defaultOptions.UnserializeOptions.Mods, defaultMods)
	require.Empty(t, defaultOptions.formatOptions)
	require.Nil(t, defaultOptions.RetrieveOptions)

	// The second reader sees the defaults, not the first reader's options
	require.Equal(t, defaultTrack, second.Options.UnserializeOptions.TrackSource)
	require.False(t, second.Options.UnserializeOptions.IsModEnabled(mod.Mod("test-mod")))
	require.Nil(t, second.Options.GetFormatOptions("driver"))
	require.Nil(t, second.Options.RetrieveOptions)

	// The first reader kept what it was given
	require.Equal(t, !defaultTrack, first.Options.UnserializeOptions.TrackSource)
	require.True(t, first.Options.UnserializeOptions.IsModEnabled(mod.Mod("test-mod")))
	require.Equal(t, "opts", first.Options.GetFormatOptions("driver"))
	require.Equal(t, "be", first.Options.RetrieveOptions.BackendOptions)

	// Mutating a reader after construction stays local too
	WithoutMod(mod.Mod("test-mod"))(first)
	WithMod(mod.Mod("test-mod"))(second)
	require.False(t, first.Options.UnserializeOptions.IsModEnabled(mod.Mod("test-mod")))
	require.True(t, second.Options.UnserializeOptions.IsModEnabled(mod.Mod("test-mod")))
	require.Len(t, defaultOptions.UnserializeOptions.Mods, defaultMods)
}

// Concurrent construction must not race; run with -race to check.
func TestNewConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			track := i%2 == 0
			r := New(WithTrackSource(track), WithMod(mod.Mod("test-mod")))
			if r.Options.UnserializeOptions.TrackSource != track {
				t.Errorf("reader %d: TrackSource %v, want %v", i, r.Options.UnserializeOptions.TrackSource, track)
			}
		})
	}
	wg.Wait()
}

func TestOptionsClone(t *testing.T) {
	var nilOpts *Options
	require.Nil(t, nilOpts.clone())

	src := &Options{
		Format:             formats.CDX16JSON,
		UnserializeOptions: &native.UnserializeOptions{TrackSource: true, Mods: map[mod.Mod]struct{}{mod.Mod("m"): {}}},
		RetrieveOptions:    &storage.RetrieveOptions{BackendOptions: "be"},
		formatOptions:      map[string]interface{}{"k": "v"},
	}
	c := src.clone()
	require.Equal(t, src, c)
	require.NotSame(t, src.UnserializeOptions, c.UnserializeOptions)
	require.NotSame(t, src.RetrieveOptions, c.RetrieveOptions)

	c.Format = formats.SPDX23JSON
	c.UnserializeOptions.TrackSource = false
	delete(c.UnserializeOptions.Mods, mod.Mod("m"))
	c.RetrieveOptions.BackendOptions = "changed"
	c.formatOptions["k"] = "changed"
	require.Equal(t, formats.CDX16JSON, src.Format)
	require.True(t, src.UnserializeOptions.TrackSource)
	require.True(t, src.UnserializeOptions.IsModEnabled(mod.Mod("m")))
	require.Equal(t, "be", src.RetrieveOptions.BackendOptions)
	require.Equal(t, "v", src.formatOptions["k"])

	// Nil nested options stay nil
	require.Nil(t, (&Options{}).clone().UnserializeOptions)
}
