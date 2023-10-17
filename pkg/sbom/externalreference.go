package sbom

import (
	"fmt"
	"maps"

	"github.com/bom-squad/protobom/pkg/formats/spdx"
)

// ToSPDX2Category returns the type of the external reference in the
// spdx 2.x vocabulary.
func (e *ExternalReference) ToSPDX2Category() string {
	switch e.ToSPDX2Type() {
	case "cpe22Type", "cpe23Type", "advisory", "fix", "url", "swid":
		return spdx.CategorySecurity
	case "maven-central", "npm", "nuget", "bower", "purl":
		return spdx.CategoryPackageManager
	case "swh", "gitoid":
		return spdx.CategoryPersistentID
	default:
		return spdx.CategoryOther
	}
}

// ToSPDX2Type converts the external reference type to the SPDX 2.x equivalent.
func (e *ExternalReference) ToSPDX2Type() string {
	// TODO: Shoud we be more prescriptive here?
	return e.Type
}

// flatString returns a deterministic string that can be used to hash the external reference
func (e *ExternalReference) flatString() string {
	ret := ""
	if e.Type != "" {
		ret += fmt.Sprintf("(t)%s", e.Type)
	}
	if e.Url != "" {
		ret += fmt.Sprintf("(u)%s", e.Url)
	}

	if e.Comment != "" {
		ret += fmt.Sprintf("(c)%s", e.Comment)
	}

	if e.Authority != "" {
		ret += fmt.Sprintf("(a)%s", e.Authority)
	}

	return ret
}

// Copy returns an exact copy of ExternalReference e.
func (e *ExternalReference) Copy() *ExternalReference {
	return &ExternalReference{
		Url:       e.Url,
		Type:      e.Type,
		Comment:   e.Comment,
		Authority: e.Authority,
		Hashes:    maps.Clone(e.Hashes),
	}
}
