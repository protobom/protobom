package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddDestinationById(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		sut    *Edge
		dest   []string
		expLen int
	}{
		{"add1", &Edge{To: []string{}}, []string{"test"}, 1},
		{"dedupe", &Edge{To: []string{"test"}}, []string{"test"}, 1},
		{"dedupe-with-existing", &Edge{To: []string{"test", "test2"}}, []string{"test"}, 2},
		{"dedupe-more-than-1", &Edge{To: []string{"test", "test2"}}, []string{"test2", "test"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.sut.AddDestinationById(tc.dest...)
			require.Len(t, tc.sut.To, tc.expLen)
		})
	}
}

func TestIndexDestinations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		sut    *Edge
		expIdx map[string]struct{}
	}{
		{"empty", &Edge{To: []string{}}, map[string]struct{}{}},
		{"single", &Edge{To: []string{"test"}}, map[string]struct{}{"test": {}}},
		{"multiple", &Edge{To: []string{"test", "test2", "test3"}}, map[string]struct{}{"test": {}, "test2": {}, "test3": {}}},
		{"nil", &Edge{}, map[string]struct{}{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ret := tc.sut.indexDestinations()
			require.Equal(t, tc.expIdx, ret)
		})
	}
}

func TestEdgeEqual(t *testing.T) {
	t.Parallel()

	// Two edges say the same thing whatever order they list the same
	// destinations in.
	a := &Edge{Type: Edge_contains, From: "root", To: []string{"b", "a"}}
	b := &Edge{Type: Edge_contains, From: "root", To: []string{"a", "b"}}
	require.True(t, a.Equal(b))

	// ...but comparing them must not reorder either one. The order of the
	// destinations is what the document said, and it is what gets written
	// back out, so a read-only comparison that sorts them in place changes
	// the output of anything that compares an edge before writing it.
	require.Equal(t, []string{"b", "a"}, a.To)
	require.Equal(t, []string{"a", "b"}, b.To)

	for name, other := range map[string]*Edge{
		"a different source":     {Type: Edge_contains, From: "elsewhere", To: []string{"a", "b"}},
		"a different type":       {Type: Edge_dependsOn, From: "root", To: []string{"a", "b"}},
		"a missing destination":  {Type: Edge_contains, From: "root", To: []string{"a"}},
		"an extra destination":   {Type: Edge_contains, From: "root", To: []string{"a", "b", "c"}},
		"different destinations": {Type: Edge_contains, From: "root", To: []string{"a", "c"}},
	} {
		t.Run(name+" is not equal", func(t *testing.T) {
			t.Parallel()
			require.False(t, a.Equal(other))
		})
	}

	require.False(t, a.Equal(nil))
}

// TestEdgePointsTo checks the destination lookup guarding edge merges.
func TestEdgePointsTo(t *testing.T) {
	t.Parallel()
	edge := &Edge{Type: Edge_dependsOn, From: "a", To: []string{"b", "c"}}
	require.True(t, edge.PointsTo("b"))
	require.True(t, edge.PointsTo("c"))
	require.False(t, edge.PointsTo("a"))
	require.False(t, edge.PointsTo("z"))
	require.False(t, (&Edge{From: "a"}).PointsTo("b"))
}
