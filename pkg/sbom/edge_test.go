package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddDestinationById(t *testing.T) {
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.sut.AddDestinationById(tc.dest...)
			require.Equal(t, tc.expLen, len(tc.sut.To))
		})
	}
}
