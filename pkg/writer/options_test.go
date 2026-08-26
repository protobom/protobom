package writer

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/native"
)

// Writers must not share the package defaults: configuring one writer
// must not change the defaults or any other writer.
func TestNewDoesNotShareDefaults(t *testing.T) {
	defaultFormat := defaultOptions.Format
	defaultIndent := defaultOptions.RenderOptions.Indent
	require.Empty(t, defaultOptions.SerializeOptions.Mods)
	require.Empty(t, defaultOptions.formatOptions)

	first := New(
		WithFormat(formats.CDX16JSON),
		WithRenderOptions(&native.RenderOptions{Indent: 2}),
		WithMod(mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS),
		WithFormatOptions("driver", "opts"),
	)
	second := New()

	// The defaults are untouched
	require.Equal(t, defaultFormat, defaultOptions.Format)
	require.Equal(t, defaultIndent, defaultOptions.RenderOptions.Indent)
	require.Empty(t, defaultOptions.SerializeOptions.Mods)
	require.Empty(t, defaultOptions.formatOptions)

	// The second writer sees the defaults, not the first writer's options
	require.Equal(t, defaultFormat, second.Options.Format)
	require.Equal(t, defaultIndent, second.Options.RenderOptions.Indent)
	require.False(t, second.Options.SerializeOptions.IsModEnabled(mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS))
	require.Nil(t, second.Options.GetFormatOptions("driver"))

	// The first writer kept what it was given
	require.Equal(t, formats.CDX16JSON, first.Options.Format)
	require.Equal(t, 2, first.Options.RenderOptions.Indent)
	require.True(t, first.Options.SerializeOptions.IsModEnabled(mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS))
	require.Equal(t, "opts", first.Options.GetFormatOptions("driver"))

	// Mutating a writer after construction stays local too
	WithoutMod(mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS)(first)
	WithMod(mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS)(second)
	require.False(t, first.Options.SerializeOptions.IsModEnabled(mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS))
	require.True(t, second.Options.SerializeOptions.IsModEnabled(mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS))
	require.Empty(t, defaultOptions.SerializeOptions.Mods)
}

// Concurrent construction must not race; run with -race to check.
func TestNewConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			format := formats.CDX16JSON
			if i%2 == 0 {
				format = formats.SPDX23JSON
			}
			w := New(WithFormat(format), WithMod(mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS))
			if w.Options.Format != format {
				t.Errorf("writer %d: format %q, want %q", i, w.Options.Format, format)
			}
		})
	}
	wg.Wait()
}

func TestOptionsClone(t *testing.T) {
	var nilOpts *Options
	require.Nil(t, nilOpts.clone())

	src := &Options{
		Format:           formats.CDX16JSON,
		RenderOptions:    &native.RenderOptions{Indent: 3},
		SerializeOptions: &native.SerializeOptions{Mods: map[mod.Mod]struct{}{mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS: {}}},
		formatOptions:    map[string]interface{}{"k": "v"},
	}
	c := src.clone()
	require.Equal(t, src, c)
	require.NotSame(t, src.RenderOptions, c.RenderOptions)
	require.NotSame(t, src.SerializeOptions, c.SerializeOptions)

	c.Format = formats.SPDX23JSON
	c.RenderOptions.Indent = 9
	delete(c.SerializeOptions.Mods, mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS)
	c.formatOptions["k"] = "changed"
	require.Equal(t, formats.CDX16JSON, src.Format)
	require.Equal(t, 3, src.RenderOptions.Indent)
	require.True(t, src.SerializeOptions.IsModEnabled(mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS))
	require.Equal(t, "v", src.formatOptions["k"])

	// Nil nested options stay nil
	require.Nil(t, (&Options{}).clone().StoreOptions)
}
