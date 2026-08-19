// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHashAlgorithmSPDX3RoundTrip checks the two SPDX 3 mappings are exact
// inverses. They are written as two switches and would otherwise drift on a
// single mistyped name, which is the kind of mistake that reads correct.
func TestHashAlgorithmSPDX3RoundTrip(t *testing.T) {
	t.Parallel()
	require.Equal(t, "adler32", HashAlgorithm_ADLER32.ToSPDX3())
	require.Equal(t, HashAlgorithm_ADLER32, HashAlgorithmFromSPDX3("adler32"))

	named := 0
	for algo := range HashAlgorithm_name {
		name := HashAlgorithm(algo).ToSPDX3()
		if name == "" {
			continue
		}
		named++
		require.Equal(t, HashAlgorithm(algo), HashAlgorithmFromSPDX3(name),
			"%s writes %q, which reads back as something else", HashAlgorithm(algo), name)
	}
	require.NotZero(t, named)

	require.Equal(t, HashAlgorithm_UNKNOWN, HashAlgorithmFromSPDX3("not-an-algorithm"))
	require.Equal(t, HashAlgorithm_UNKNOWN, HashAlgorithmFromSPDX3(""))
}
