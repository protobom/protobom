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
