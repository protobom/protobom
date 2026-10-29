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
