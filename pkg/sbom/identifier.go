package sbom

import (
	"strings"

	"github.com/protobom/protobom/pkg/formats/spdx"
)

// SoftwareIdentifierTypeFromString resolves a string into one of our built-in
// identifier types.
func SoftwareIdentifierTypeFromString(queryString string) SoftwareIdentifierType {
	// If its an SPDX type, use it
	if r := SoftwareIdentifierTypeFromSPDXExtRefType(queryString); r != SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE {
		return r
	}

	queryString = strings.TrimSpace(strings.ToLower(queryString))
	switch queryString {
	case "cpe22", "cpe2.2":
		return SoftwareIdentifierType_CPE22
	case "cpe23", "cpe2.3":
		return SoftwareIdentifierType_CPE23
	default:
		return SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE
	}
}

// Deprecated: SoftwareIdentifierTypeFromSPDXExtRefType is deprecated and will
// be removed in an upcoming version. Please use SoftwareIdentifierTypeFromString
// for a unified approach to identifier resolution.
func SoftwareIdentifierTypeFromSPDXExtRefType(spdxType string) SoftwareIdentifierType {
	switch spdxType {
	case spdx.ExtRefTypePurl:
		return SoftwareIdentifierType_PURL
	case spdx.ExtRefTypeCPE22:
		return SoftwareIdentifierType_CPE22
	case spdx.ExtRefTypeCPE23:
		return SoftwareIdentifierType_CPE23
	case spdx.ExtRefTypeGitoid:
		return SoftwareIdentifierType_GITOID
	default:
		return SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE
	}
}

// ToSPDX2Category converts the external reference type to its SPDX2 category.
func (i SoftwareIdentifierType) ToSPDX2Category() string {
	switch i.ToSPDX2Type() {
	case spdx.ExtRefTypeCPE22, spdx.ExtRefTypeCPE23, "advisory", "fix", "url", "swid":
		return spdx.CategorySecurity
	case "maven-central", "npm", "nuget", "bower", spdx.ExtRefTypePurl:
		return spdx.CategoryPackageManager
	case "swh", spdx.ExtRefTypeGitoid:
		return spdx.CategoryPersistentID
	default:
		return spdx.CategoryOther
	}
}

// ToSPDX2Type converts the external reference type to its SPDX2 equivalent.
func (i SoftwareIdentifierType) ToSPDX2Type() string {
	switch i {
	case SoftwareIdentifierType_PURL:
		return spdx.ExtRefTypePurl
	case SoftwareIdentifierType_CPE22:
		return spdx.ExtRefTypeCPE22
	case SoftwareIdentifierType_CPE23:
		return spdx.ExtRefTypeCPE23
	case SoftwareIdentifierType_GITOID:
		return spdx.ExtRefTypeGitoid
	default:
		return ""
	}
}
