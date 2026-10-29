// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package licenselist

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	require.Regexp(t, `^\d+\.\d+\.\d+$`, Version)
}

func TestLicense(t *testing.T) {
	for name, tc := range map[string]struct {
		id         string
		canonical  string
		deprecated bool
		ok         bool
	}{
		"listed":                 {"Apache-2.0", "Apache-2.0", false, true},
		"case insensitive":       {"apache-2.0", "Apache-2.0", false, true},
		"surrounding whitespace": {" MIT ", "MIT", false, true},
		"deprecated":             {"GPL-2.0", "GPL-2.0", true, true},
		"deprecated plus":        {"GPL-2.0+", "GPL-2.0+", true, true},
		"exception is not a license": {
			"Classpath-exception-2.0", "", false, false,
		},
		"license reference": {"LicenseRef-GPL", "", false, false},
		"expression":        {"MIT OR Apache-2.0", "", false, false},
		"free form name":    {"GPL", "", false, false},
		"empty":             {"", "", false, false},
		"not a license at all": {
			"not a license", "", false, false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			canonical, deprecated, ok := License(tc.id)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.canonical, canonical)
			require.Equal(t, tc.deprecated, deprecated)
			require.Equal(t, tc.ok, IsLicense(tc.id))
		})
	}
}

func TestException(t *testing.T) {
	for name, tc := range map[string]struct {
		id         string
		canonical  string
		deprecated bool
		ok         bool
	}{
		"listed":           {"Classpath-exception-2.0", "Classpath-exception-2.0", false, true},
		"case insensitive": {"classpath-EXCEPTION-2.0", "Classpath-exception-2.0", false, true},
		"deprecated":       {"Nokia-Qt-exception-1.1", "Nokia-Qt-exception-1.1", true, true},
		"license is not an exception": {
			"MIT", "", false, false,
		},
		"empty": {"", "", false, false},
	} {
		t.Run(name, func(t *testing.T) {
			canonical, deprecated, ok := Exception(tc.id)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.canonical, canonical)
			require.Equal(t, tc.deprecated, deprecated)
			require.Equal(t, tc.ok, IsException(tc.id))
		})
	}
}

// The generated data must index cleanly: no two identifiers may collide
// once case is ignored, or the lookup would be ambiguous.
func TestNoCaseCollisions(t *testing.T) {
	index()
	require.Len(t, licenseIndex, len(licenses))
	require.Len(t, exceptionIndex, len(exceptions))
}

func TestShortVersion(t *testing.T) {
	require.Regexp(t, `^\d+\.\d+$`, ShortVersion())
	require.True(t, strings.HasPrefix(Version, ShortVersion()+"."))
}
