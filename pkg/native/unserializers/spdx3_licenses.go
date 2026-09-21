// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package unserializers

import (
	"strings"

	"github.com/carabiner-dev/spdx3/profiles/core"
	"github.com/carabiner-dev/spdx3/profiles/expandedlicensing"
	"github.com/carabiner-dev/spdx3/profiles/simplelicensing"
	spdx3types "github.com/carabiner-dev/spdx3/types"

	protospdx "github.com/protobom/protobom/pkg/formats/spdx"
)

// licenses folds the licensing back into the elements it belongs to.
//
// SPDX 3 does not carry licensing in a field. It states it as a licence
// element in the graph and a relationship pointing at it, so reading it
// means consuming both: the elements must not become nodes and the
// relationships must not become edges, or the document gains a graph it
// never had. Nothing here adds to the node list; it only fills in fields.
func (rd *spdx3Reader) licenses() {
	for _, element := range rd.env.Graph {
		relationship, ok := element.(*core.Relationship)
		if !ok {
			continue
		}

		declared := relationship.RelationshipType == core.RelationshipTypeHasDeclaredLicense
		if !declared && relationship.RelationshipType != core.RelationshipTypeHasConcludedLicense {
			continue
		}
		if relationship.From == nil {
			continue
		}
		node, ok := rd.nodes[relationship.From.GetSPDXID()]
		if !ok {
			// The licence belongs to an element protobom did not read: the
			// corpus states licences for AI and dataset packages too.
			continue
		}

		for _, target := range relationship.To {
			expression, ok := licenseFromSPDX3(target)
			if !ok {
				continue
			}
			if declared {
				node.Licenses = append(node.Licenses, protospdx.SplitLicenses(expression, protospdx.OperatorAND)...)
				continue
			}
			// TODO(degradation): protobom concludes a single licence, so an
			// element with more than one concluded keeps the first.
			if node.LicenseConcluded == "" {
				node.LicenseConcluded = expression
			}
		}
	}
}

// licenseFromSPDX3 returns the licence expression an element states, and
// whether it states one at all.
//
// Only SimpleLicensing's LicenseExpression does. It is what the profiles
// protobom reads use, and what 222 of the 224 licence relationships in the
// SPDX examples corpus point at.
//
// TODO(degradation): the other two point at ExpandedLicensing classes, which
// state a licence as a text and a name rather than as an expression.
// Protobom holds a licence as an expression, and neither a licence text nor
// a human name is one, so those are dropped rather than written back out as
// an expression that is not valid. Reading ExpandedLicensing would be its
// own decision, as Security was.
//
// A NOASSERTION says the document declines to state a licence, so it is not
// read as one, which is what the SPDX 2 reader does with it too. NONE and
// NOASSERTION are read both as expressions and as the individuals the
// specification predefines for them, which documents reference by IRI.
func licenseFromSPDX3(node spdx3types.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	// The individuals are never written out, so a reference to one is left
	// unresolved and carries its IRI as a bare reference.
	id := node.GetSPDXID()
	if ref, ok := node.(spdx3types.NodeRef); ok {
		id = ref.ID
	}
	switch id {
	case protospdx.SPDX3NoneLicenseIRI, expandedlicensing.NoneLicenseIRI, spdx3NoneLicenseCompact:
		return protospdx.NONE, true
	case protospdx.SPDX3NoAssertionLicenseIRI, expandedlicensing.NoAssertionLicenseIRI, spdx3NoAssertionLicenseCompact:
		return "", false
	}

	expression, ok := node.(*simplelicensing.LicenseExpression)
	if !ok {
		return "", false
	}
	license := strings.TrimSpace(expression.LicenseExpression)
	if license == "" || strings.EqualFold(license, protospdx.NOASSERTION) {
		return "", false
	}
	if strings.EqualFold(license, protospdx.NONE) {
		return protospdx.NONE, true
	}
	return expression.LicenseExpression, true
}

// The compact names of the licensing individuals. The JSON-LD context
// declares the relationship's "to" property with "@type": "@vocab", so a
// document may name them relative to the vocabulary instead of by IRI.
const (
	spdx3NoneLicenseCompact        = "expandedlicensing_NoneLicense"
	spdx3NoAssertionLicenseCompact = "expandedlicensing_NoAssertionLicense"
)
