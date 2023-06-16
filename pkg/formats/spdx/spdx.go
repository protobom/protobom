// SPDX-FileCopyrightText: Copyright 2023 The BOM Squad Authors
// SPDX-License-Identifier: Apache-2.0

package spdx

import "strings"

const (
	NOASSERTION = "NOASSERTION"
)

// ParseActorString parses an SPDX "actor string", it is a specially formatted
// string that contains the type of actor (Person/Organization), their name and
// optionally an email address. For example, the following string:
//
// "Person: Debian OpenLDAP Maintainers (pkg-openldap-devel@lists.alioth.debian.org)"
//
// would return:
// "Organization", "Debian OpenLDAP Maintainers", "pkg-openldap-devel@lists.alioth.debian.org"
func ParseActorString(s string) (actorType, actorName, actorEmail string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "Person:") {
		actorType = "person"
		s = strings.TrimPrefix(s, "Person:")
	} else if strings.HasPrefix(s, "Organization:") {
		actorType = "org"
		s = strings.TrimPrefix(s, "Organization:")
	}
	s = strings.TrimSpace(s)
	actorName = s
	if strings.HasSuffix(s, ")") && strings.Contains(s, "(") {
		actorName = strings.TrimSpace(s[0:strings.LastIndex(s, "(")])
		actorEmail = strings.TrimSpace(s[strings.LastIndex(s, "(")+1:])
		actorEmail = strings.TrimSuffix(actorEmail, ")")
	}

	return actorType, actorName, actorEmail
}
