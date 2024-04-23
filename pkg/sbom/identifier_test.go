package sbom

import (
	"testing"

	"github.com/protobom/protobom/pkg/formats/spdx"
	"github.com/stretchr/testify/require"
)

func TestIToSPDX2Category(t *testing.T) {
	for _, tc := range []struct {
		sut      SoftwareIdentifierType
		expected string
	}{
		{SoftwareIdentifierType_PURL, spdx.CategoryPackageManager},
		{SoftwareIdentifierType_CPE23, spdx.CategorySecurity},
		{SoftwareIdentifierType_CPE22, spdx.CategorySecurity},
		{SoftwareIdentifierType_GITOID, spdx.CategoryPersistentID},
		{SoftwareIdentifierType(328742873), spdx.CategoryOther},
	} {
		require.Equal(t, tc.expected, tc.sut.ToSPDX2Category())
	}
}

func TestIToSPDX2Type(t *testing.T) {
	for _, tc := range []struct {
		sut      SoftwareIdentifierType
		expected string
	}{
		{SoftwareIdentifierType_PURL, spdx.ExtRefTypePurl},
		{SoftwareIdentifierType_CPE23, spdx.ExtRefTypeCPE23},
		{SoftwareIdentifierType_CPE22, spdx.ExtRefTypeCPE22},
		{SoftwareIdentifierType_GITOID, spdx.ExtRefTypeGitoid},
		{SoftwareIdentifierType(1234123415), ""},
	} {
		require.Equal(t, tc.expected, tc.sut.ToSPDX2Type())
	}
}
