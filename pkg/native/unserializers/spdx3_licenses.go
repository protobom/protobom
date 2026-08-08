// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package unserializers

import (
	"strings"

	"github.com/carabiner-dev/spdx3/profiles/core"
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
				node.Licenses = append(node.Licenses, splitConjunction(expression)...)
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
// read as one, which is what the SPDX 2 reader does with it too.
func licenseFromSPDX3(node spdx3types.Node) (string, bool) {
	expression, ok := node.(*simplelicensing.LicenseExpression)
	if !ok {
		return "", false
	}
	if expression.LicenseExpression == "" || expression.LicenseExpression == protospdx.NOASSERTION {
		return "", false
	}
	return expression.LicenseExpression, true
}

// splitConjunction takes apart an expression that is nothing but licences
// joined by AND, which is how the writer states protobom's list of declared
// licences as the single expression SPDX 3 wants.
//
// It splits only when there is nothing else in the expression: a bracket or
// an OR means the licences relate to each other in a way a flat list cannot
// hold, and a piece of such an expression is not a licence. So
// "MIT AND Apache-2.0" comes apart and "(BSD-3-Clause AND GPL-3.0-or-later)"
// does not.
func splitConjunction(expression string) []string {
	if strings.ContainsAny(expression, "()") || strings.Contains(expression, " OR ") {
		return []string{expression}
	}

	licenses := strings.Split(expression, " AND ")
	for i := range licenses {
		licenses[i] = strings.TrimSpace(licenses[i])
	}
	return licenses
}
