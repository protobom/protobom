package sbom

import (
	"fmt"
	"maps"
)

// flatString returns a deterministic string that can be used to hash the external reference
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
