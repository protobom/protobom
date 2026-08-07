// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package serializers

import (
	"crypto/sha1" //nolint:gosec // the algorithm is fixed by the SPDX specification
	"fmt"
	"sort"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
)

// packageVerificationCode computes the verification code of a package, the
// value SPDX defines to let a consumer check that the files it received are
// the files the document describes.
//
// It is the SHA1 of the SHA1 hashes of the package's files: each file's hash
// written in lowercase hexadecimal, the hashes sorted, concatenated with
// nothing between them, and hashed again. See section 7.9 of the SPDX 2.3
// specification, which SPDX 3 carries over unchanged in
// /Core/PackageVerificationCode.
//
// The code is not stored in the protobom data: it is computed from the document's
// own contents, so reading a document and writing it back recomputes it.
//
// An empty string means the code cannot be computed and none should be
// written: either the package has no files, or one of them has no SHA1, in
// which case the value would be a hash of an incomplete list and worse than
// no value at all.
func packageVerificationCode(nl *sbom.NodeList, pkg *sbom.Node) string {
	if nl == nil || pkg == nil || pkg.Type != sbom.Node_PACKAGE {
		return ""
	}

	// A node can be the source of more than one edge of the same type, so
	// every contains edge is walked rather than just the first.
	hashes := []string{}
	for _, edge := range nl.Edges {
		if edge.From != pkg.Id || edge.Type != sbom.Edge_contains {
			continue
		}
		for _, id := range edge.To {
			file := nl.GetNodeByID(id)
			if file == nil || file.Type != sbom.Node_FILE {
				continue
			}

			sha := file.Hashes[int32(sbom.HashAlgorithm_SHA1)]
			if sha == "" {
				// A file with no SHA1 makes the code meaningless, as it
				// would stand for a list of files that is not the package's.
				return ""
			}
			hashes = append(hashes, strings.ToLower(sha))
		}
	}

	if len(hashes) == 0 {
		return ""
	}

	sort.Strings(hashes)

	//nolint:gosec // sha1 is fixed by the SPDX specification
	return fmt.Sprintf("%x", sha1.Sum([]byte(strings.Join(hashes, ""))))
}
