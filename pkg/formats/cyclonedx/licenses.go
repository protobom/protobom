// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package cyclonedx

import "strings"

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
