package sbom

import (
	"testing"

	"github.com/bom-squad/protobom/pkg/formats/spdx"
	"github.com/stretchr/testify/require"
)

func TestIToSPDX2Category(t *testing.T) {
	for _, tc := range []struct {
		sut      string
		expected string
	}{
		{"cpe22", spdx.CategorySecurity},
		{"cpe23", spdx.CategorySecurity},
		{"advisory", spdx.CategorySecurity},
		{"fix", spdx.CategorySecurity},
		{"url", spdx.CategorySecurity},
		{"swid", spdx.CategorySecurity},

		{"maven-central", spdx.CategoryPackageManager},
		{"npm", spdx.CategoryPackageManager},
		{"nuget", spdx.CategoryPackageManager},
		{"bower", spdx.CategoryPackageManager},
		{"purl", spdx.CategoryPackageManager},

		{"swh", spdx.CategoryPersistentID},
		{"gitoid", spdx.CategoryPersistentID},

		{"", spdx.CategoryOther},
		{"lkjsedlfkjsldkj", spdx.CategoryOther},
	} {
		identifier := Identifier{
			Type:  tc.sut,
			Value: "does not matter",
		}
		cat := identifier.ToSPDX2Category()
		require.Equal(t, tc.expected, cat)
	}
}
