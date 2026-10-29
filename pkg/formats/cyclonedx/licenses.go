// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package cyclonedx

import "strings"

const (
	// LicenseRefPrefix is the prefix of an SPDX license reference, the form
	// an expression takes to name a license that is not in the SPDX list.
	LicenseRefPrefix = "LicenseRef-"

	// NamedLicenseRefPrefix marks a license reference protobom minted from a
	// CycloneDX license that only had a name. The marker tells the reference
	// apart from one an SPDX document defined, so the serializer can write
	// it back as a name while leaving a genuine reference untouched.
	NamedLicenseRefPrefix = LicenseRefPrefix + "x-protobom-"
)

// NamedLicenseRef mints the license reference protobom carries a CycloneDX
// license that only has a name as. The name is restricted to the characters
// an SPDX license reference admits (letters, digits, dot and dash): any
// other run of characters becomes a single dash and dashes at either end
// are dropped. It returns an empty string when nothing of the name survives.
// TODO(degradation): the original spelling of a name that needed changes
// is lost.
func NamedLicenseRef(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		default:
			dash = true
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return NamedLicenseRefPrefix + b.String()
}

// LicenseNameFromRef returns the name carried by a license reference protobom
// minted from a CycloneDX license name, and whether the string is one.
func LicenseNameFromRef(license string) (string, bool) {
	name, ok := strings.CutPrefix(license, NamedLicenseRefPrefix)
	if !ok || name == "" {
		return "", false
	}
	return name, true
}

// IsLicenseRef reports whether a license string is an SPDX license reference.
func IsLicenseRef(license string) bool {
	return strings.HasPrefix(license, LicenseRefPrefix)
}

// DerivedConcludedLicense returns the concluded license protobom derives
// from a component's declared license list when the CycloneDX document does
// not state one through the license acknowledgement: the single declared
// license, or the declared entries joined with OR.
//
// The unserializer uses it to fill the concluded license and the serializer
// to recognize a concluded license that merely restates the declared list,
// so it does not write it back as an extra, acknowledged entry.
func DerivedConcludedLicense(declared []string) string {
	parts := make([]string, 0, len(declared))
	for _, l := range declared {
		if l != "" {
			parts = append(parts, l)
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts, " OR ")
}
