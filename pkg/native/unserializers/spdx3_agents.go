// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package unserializers

import (
	"strings"
	"unicode"

	"github.com/carabiner-dev/spdx3/profiles/core"
	spdx3types "github.com/carabiner-dev/spdx3/types"

	"github.com/protobom/protobom/pkg/sbom"
)

// agentFromSPDX3 reads an agent element into a protobom person, and says
// whether the element was an agent at all.
//
// SPDX 3 has three kinds where protobom has one: a Person is a person, an
// Organization is one with IsOrg, and a SoftwareAgent — something acting on
// its own behalf, such as a scanner — is one with IsSoftwareAgent.
//
// Anything else is not an agent. In particular the model's predefined
// SpdxOrganization, which a document names when it will not say who created
// it, is a bare reference with nothing behind it: it says the author is
// unstated, so reading it as an author named "" would state the opposite.
func agentFromSPDX3(node spdx3types.Node) (*sbom.Person, bool) {
	if node == nil {
		return nil, false
	}
	switch agent := node.(type) {
	case *core.Person:
		return withIdentifiers(&sbom.Person{Name: agent.Name}, agent.ExternalIdentifier), true
	case *core.Organization:
		return withIdentifiers(&sbom.Person{Name: agent.Name, IsOrg: true}, agent.ExternalIdentifier), true
	case *core.SoftwareAgent:
		return &sbom.Person{Name: agent.Name, IsSoftwareAgent: true}, true
	default:
		return nil, false
	}
}

// withIdentifiers takes the ways of reaching an agent out of the external
// identifiers SPDX 3 states them as.
//
// TODO(degradation): protobom holds one email and one URL, so an agent
// reachable at several of either keeps the first. Its phone number and
// contacts have no SPDX 3 property to come from at all.
func withIdentifiers(person *sbom.Person, identifiers []core.ExternalIdentifier) *sbom.Person {
	for _, id := range identifiers {
		switch id.ExternalIdentifierType {
		case core.ExternalIdentifierTypeEmail:
			if person.Email == "" {
				person.Email = id.Identifier
			}
		case core.ExternalIdentifierTypeUrlScheme:
			if person.Url == "" {
				person.Url = id.Identifier
			}
		}
	}
	return person
}

// toolFromSPDX3 reads a tool element, and says whether the element was one.
//
// SPDX 3's Tool has a name and nothing else, so protobom's writer joins the
// name and version with a dash and the reader has to decide where to take
// them apart again. It splits only when what follows the last dash looks
// like a version, which leaves alone the tools that are named with dashes —
// spdx-maven-plugin keeps its name, Microsoft.SBOMTool-0.2.7 gets its
// version back, and protobom-v1.2.3 comes back as it went out.
//
// TODO(degradation): a tool whose version does not start with a digit is
// read as part of its name, and a tool's vendor has nowhere to come from.
func toolFromSPDX3(node spdx3types.Node) (*sbom.Tool, bool) {
	tool, ok := node.(*core.Tool)
	if !ok {
		return nil, false
	}

	name, version := tool.Name, ""
	if dash := strings.LastIndex(name, "-"); dash > 0 && looksLikeVersion(name[dash+1:]) {
		name, version = name[:dash], name[dash+1:]
	}
	return &sbom.Tool{Name: name, Version: version}, true
}

// looksLikeVersion says whether a string is one a tool would be versioned
// with: a digit, or a v before one.
func looksLikeVersion(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	return s != "" && unicode.IsDigit(rune(s[0]))
}
