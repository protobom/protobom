package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/formats/spdx"
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
		{SoftwareIdentifierType_SWHID, spdx.CategoryPersistentID},
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
		{SoftwareIdentifierType_SWHID, spdx.ExtRefTypeSwh},
		{SoftwareIdentifierType(1234123415), ""},
	} {
		require.Equal(t, tc.expected, tc.sut.ToSPDX2Type())
	}
}

func TestSoftwareIdentifierTypeFromString(t *testing.T) {
	for _, tc := range []struct {
		query    string
		expected SoftwareIdentifierType
	}{
		// The SPDX external reference spellings resolve as they are written.
		{spdx.ExtRefTypePurl, SoftwareIdentifierType_PURL},
		{spdx.ExtRefTypeCPE22, SoftwareIdentifierType_CPE22},
		{spdx.ExtRefTypeCPE23, SoftwareIdentifierType_CPE23},
		{spdx.ExtRefTypeGitoid, SoftwareIdentifierType_GITOID},

		// Every type also resolves from its own name, whatever the case and
		// surrounding space, including the name the enum itself prints.
		{"purl", SoftwareIdentifierType_PURL},
		{"PURL", SoftwareIdentifierType_PURL},
		{"  Purl ", SoftwareIdentifierType_PURL},
		{"gitoid", SoftwareIdentifierType_GITOID},
		{"GITOID", SoftwareIdentifierType_GITOID},
		{" GitOID", SoftwareIdentifierType_GITOID},
		{"cpe22", SoftwareIdentifierType_CPE22},
		{"CPE22", SoftwareIdentifierType_CPE22},
		{"cpe2.2", SoftwareIdentifierType_CPE22},
		{"cpe23", SoftwareIdentifierType_CPE23},
		{"CPE23", SoftwareIdentifierType_CPE23},
		{"cpe2.3", SoftwareIdentifierType_CPE23},

		{"", SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE},
		{"swh", SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE},
		{"not-an-identifier", SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE},
	} {
		require.Equal(t, tc.expected, SoftwareIdentifierTypeFromString(tc.query), "resolving %q", tc.query)
	}
}

func TestSoftwareIdentifierTypeFromStringRoundTrip(t *testing.T) {
	for _, tc := range []SoftwareIdentifierType{
		SoftwareIdentifierType_PURL,
		SoftwareIdentifierType_CPE22,
		SoftwareIdentifierType_CPE23,
		SoftwareIdentifierType_GITOID,
	} {
		require.Equal(t, tc, SoftwareIdentifierTypeFromString(tc.String()), "round tripping %s", tc)
	}
}
