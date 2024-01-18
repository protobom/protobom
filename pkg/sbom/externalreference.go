package sbom

import (
	"fmt"
	"maps"
)

// flatString returns a deterministic serialized representation of the external reference as a string.
// The resulting string is suitable for indexing or generating a hash.
func (e *ExternalReference) flatString() string {
	ret := fmt.Sprintf("(t)%d", e.Type)

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

// Copy returns an exact duplicate of the external reference.
func (e *ExternalReference) Copy() *ExternalReference {
	return &ExternalReference{
		Url:       e.Url,
		Type:      e.Type,
		Comment:   e.Comment,
		Authority: e.Authority,
		Hashes:    maps.Clone(e.Hashes),
	}
}
