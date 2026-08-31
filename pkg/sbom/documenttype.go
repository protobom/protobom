package sbom

import "fmt"

// flatString returns a deterministic serialized representation of the
// document type as a string, suitable for indexing or comparison of its
// contents.
func (dt *DocumentType) flatString() string {
	s := ""
	if dt.Type != nil {
		s += fmt.Sprintf("t(%s)", dt.Type.String())
	}
	if dt.Name != nil {
		s += fmt.Sprintf("n(%s)", *dt.Name)
	}
	if dt.Description != nil {
		s += fmt.Sprintf("d(%s)", *dt.Description)
	}
	return s
}
