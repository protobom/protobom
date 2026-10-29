// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

// Package licenselist embeds the SPDX License List: the identifiers of the
// licenses and license exceptions an SPDX license expression can name. It
// is format neutral, any serializer or unserializer can use it to tell a
// listed identifier from a free-form license name.
//
// The data is generated from a release of the SPDX license-list-data
// repository. The release is pinned in the VERSION file next to this one
// and the generated data is rebuilt with:
//
//	make licenselist
//
// Identifiers match without regard to case, as the SPDX specification
// requires, and the canonical spelling is returned.
package licenselist

import (
	"strings"
	"sync"
)

// entry is an identifier of the list and whether the list deprecates it.
type entry struct {
	ID         string
	Deprecated bool
}

var (
	indexOnce      sync.Once
	licenseIndex   map[string]entry
	exceptionIndex map[string]entry
)

func index() {
	indexOnce.Do(func() {
		licenseIndex = make(map[string]entry, len(licenses))
		for _, e := range licenses {
			licenseIndex[strings.ToLower(e.ID)] = e
		}
		exceptionIndex = make(map[string]entry, len(exceptions))
		for _, e := range exceptions {
			exceptionIndex[strings.ToLower(e.ID)] = e
		}
	})
}

// License looks up a license identifier. It returns the canonical spelling,
// whether the list deprecates the identifier, and whether it is listed at all.
func License(id string) (canonical string, deprecated, ok bool) {
	index()
	e, ok := licenseIndex[strings.ToLower(strings.TrimSpace(id))]
	return e.ID, e.Deprecated, ok
}

// Exception looks up a license exception identifier. It returns the canonical
// spelling, whether the list deprecates the identifier, and whether it is
// listed at all.
func Exception(id string) (canonical string, deprecated, ok bool) {
	index()
	e, ok := exceptionIndex[strings.ToLower(strings.TrimSpace(id))]
	return e.ID, e.Deprecated, ok
}

// IsLicense reports whether id is a listed license identifier, deprecated or
// not.
func IsLicense(id string) bool {
	_, _, ok := License(id)
	return ok
}

// IsException reports whether id is a listed license exception identifier,
// deprecated or not.
func IsException(id string) bool {
	_, _, ok := Exception(id)
	return ok
}
