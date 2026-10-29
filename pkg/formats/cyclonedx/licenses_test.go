// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package cyclonedx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDerivedConcludedLicense(t *testing.T) {
	for name, tc := range map[string]struct {
		declared []string
		expected string
	}{
		"none":              {nil, ""},
		"empty entry":       {[]string{""}, ""},
		"single":            {[]string{"MIT"}, "MIT"},
		"several":           {[]string{"MIT", "Apache-2.0"}, "MIT OR Apache-2.0"},
		"expression":        {[]string{"(MIT OR GPL-2.0-only)"}, "(MIT OR GPL-2.0-only)"},
		"skips empty entry": {[]string{"MIT", "", "Apache-2.0"}, "MIT OR Apache-2.0"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.expected, DerivedConcludedLicense(tc.declared))
		})
	}
}

func TestLicenseNameFromRef(t *testing.T) {
	for license, tc := range map[string]struct {
		name string
		ok   bool
	}{
		"LicenseRef-x-protobom-GPL":   {"GPL", true},
		"LicenseRef-x-protobom-":      {"", false},
		"LicenseRef-GPL":              {"", false},
		"MIT":                         {"", false},
		"LicenseRef-x-protobom-a.b-c": {"a.b-c", true},
	} {
		t.Run(license, func(t *testing.T) {
			name, ok := LicenseNameFromRef(license)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.name, name)
		})
	}
}

func TestIsLicenseRef(t *testing.T) {
	require.True(t, IsLicenseRef("LicenseRef-GPL"))
	require.True(t, IsLicenseRef("LicenseRef-x-protobom-GPL"))
	require.False(t, IsLicenseRef("MIT"))
	require.False(t, IsLicenseRef("MIT OR LicenseRef-GPL"))
}
