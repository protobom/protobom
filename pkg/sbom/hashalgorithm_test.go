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

// TestHashAlgorithmSPDX3Names pins the names of the algorithms SPDX 3 and
// protobom both know, and that the ones only SPDX 3 names stay unknown.
func TestHashAlgorithmSPDX3Names(t *testing.T) {
	t.Parallel()
	for algo, name := range map[HashAlgorithm]string{
		HashAlgorithm_ADLER32:     "adler32",
		HashAlgorithm_MD2:         "md2",
		HashAlgorithm_MD4:         "md4",
		HashAlgorithm_MD5:         "md5",
		HashAlgorithm_MD6:         "md6",
		HashAlgorithm_SHA1:        "sha1",
		HashAlgorithm_SHA224:      "sha224",
		HashAlgorithm_SHA256:      "sha256",
		HashAlgorithm_SHA384:      "sha384",
		HashAlgorithm_SHA512:      "sha512",
		HashAlgorithm_SHA3_256:    "sha3_256",
		HashAlgorithm_SHA3_384:    "sha3_384",
		HashAlgorithm_SHA3_512:    "sha3_512",
		HashAlgorithm_BLAKE2B_256: "blake2b256",
		HashAlgorithm_BLAKE2B_384: "blake2b384",
		HashAlgorithm_BLAKE2B_512: "blake2b512",
		HashAlgorithm_BLAKE3:      "blake3",
	} {
		require.Equal(t, name, algo.ToSPDX3(), algo)
		require.Equal(t, algo, HashAlgorithmFromSPDX3(name), name)
	}

	// Named by SPDX 3 only.
	for _, name := range []string{"sha3_224", "crystalsKyber", "crystalsDilithium", "falcon", "other"} {
		require.Equal(t, HashAlgorithm_UNKNOWN, HashAlgorithmFromSPDX3(name), name)
	}
	require.Empty(t, HashAlgorithm_UNKNOWN.ToSPDX3())
}
