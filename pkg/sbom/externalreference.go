package sbom

// ToSPDX2Category returns the type of the external reference in the
// spdx 2.x vocabulary.
func (e *ExternalReference) ToSPDX2Category() string {
	switch e.ToSPDX2Type() {
	case "cpe22Type", "cpe23Type", "advisory", "fix", "url", "swid":
		return "SECURITY"
	case "maven-central", "npm", "nuget", "bower", "purl":
		return "PACKAGE-MANAGER"
	case "swh", "gitoid":
		return "PERSISTENT-ID"
	default:
		return "OTHER"
	}
}

// ToSPDX2Type converts the external reference type to the SPDX 2.x equivalent.
func (e *ExternalReference) ToSPDX2Type() string {
	// TODO: Shoud we be mopre prescriptive here?
	return e.Type
}
