package sbom

import "fmt"

// flatString returns a deterministic serialized representation of the tool
// as a string, suitable for indexing or comparison of its contents.
func (t *Tool) flatString() string {
	return fmt.Sprintf("n(%s)ver(%s)v(%s)", t.Name, t.Version, t.Vendor)
}
