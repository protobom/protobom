package sbom

import (
	"fmt"

	"github.com/bom-squad/protobom/pkg/formats/spdx"
)

// flatstring returns a deterministic string that can be used to hash the identifier
func (i *Identifier) flatString() string {
	return fmt.Sprintf("bomsquad.protobom.Node.identifiers[%s]:%s", i.Type, i.Value)
}

// ToSPDX2Category returns the type of the external reference in the
// spdx 2.x vocabulary.
func (i *Identifier) ToSPDX2Category() string {
	switch i.ToSPDX2Type() {
	case "cpe22", "cpe23", "advisory", "fix", "url", "swid":
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
func (i *Identifier) ToSPDX2Type() string {
	// TODO: Should we be more prescriptive here?
	return i.Type
}
