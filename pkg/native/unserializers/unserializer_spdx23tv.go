package unserializers

import (
	"fmt"
	"io"

	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/spdx/tools-golang/tagvalue"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

var _ native.Unserializer = &SPDX23TV{}

// SPDX23TV parses SPDX 2.3 documents in tag-value encoding. The
// conversion of the parsed document is shared with the JSON
// unserializer, only the decoding differs.
type SPDX23TV struct {
	SPDX23
}

func NewSPDX23TV() *SPDX23TV {
	return &SPDX23TV{}
}

// Unserialize reads an SPDX 2.3 tag-value document from the stream and
// returns its protobom representation.
func (u *SPDX23TV) Unserialize(r io.Reader, opts *native.UnserializeOptions, _ interface{}) (*sbom.Document, error) {
	spdxDoc, err := tagvalue.Read(r)
	if err != nil {
		return nil, fmt.Errorf("parsing SPDX tag-value: %w", err)
	}
	hoistPackageFiles(spdxDoc)
	return u.unserializeDocument(spdxDoc, opts)
}

// hoistPackageFiles moves files nested in packages to the document
// level, keeping a CONTAINS relationship in their place. The tag-value
// parser attaches the file sections that follow a package to that
// package, but the shared document conversion reads files from the
// document level only (as json has no nested files) so without
// hoisting them to the doc level, the package files would be lost.
func hoistPackageFiles(doc *spdx23.Document) {
	seen := map[common.ElementID]bool{}
	for _, f := range doc.Files {
		seen[f.FileSPDXIdentifier] = true
	}
	related := map[common.ElementID]map[common.ElementID]bool{}
	for _, rel := range doc.Relationships {
		if rel.Relationship == common.TypeRelationshipContains {
			if related[rel.RefA.ElementRefID] == nil {
				related[rel.RefA.ElementRefID] = map[common.ElementID]bool{}
			}
			related[rel.RefA.ElementRefID][rel.RefB.ElementRefID] = true
		}
	}
	for _, p := range doc.Packages {
		for _, f := range p.Files {
			if !seen[f.FileSPDXIdentifier] {
				doc.Files = append(doc.Files, f)
				seen[f.FileSPDXIdentifier] = true
			}
			if !related[p.PackageSPDXIdentifier][f.FileSPDXIdentifier] {
				doc.Relationships = append(doc.Relationships, &spdx23.Relationship{
					RefA:         common.DocElementID{ElementRefID: p.PackageSPDXIdentifier},
					RefB:         common.DocElementID{ElementRefID: f.FileSPDXIdentifier},
					Relationship: common.TypeRelationshipContains,
				})
			}
		}
		p.Files = nil
	}
}
