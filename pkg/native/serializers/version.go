// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package serializers

import (
	"runtime/debug"
	"strings"
	"sync"

	protospdx "github.com/protobom/protobom/pkg/formats/spdx"
)

const (
	// protobomModule is the path of the protobom Go module.
	protobomModule = "github.com/protobom/protobom"

	// develVersion is the version reported when protobom's own is unknown,
	// such as in a build from a local checkout.
	develVersion = "devel"
)

// protobomVersion returns the version of the protobom module linked into the
// running binary. It reads the build information rather than the version of
// the binary itself, which belongs to whatever program embeds protobom. The
// build information does not change while the program runs, so it is read
// once.
var protobomVersion = sync.OnceValue(func() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return develVersion
	}
	return protobomVersionFromBuildInfo(info)
})

func protobomVersionFromBuildInfo(info *debug.BuildInfo) string {
	if info == nil {
		return develVersion
	}
	module := &info.Main
	if module.Path != protobomModule {
		module = nil
		for _, dep := range info.Deps {
			if dep != nil && dep.Path == protobomModule {
				module = dep
				break
			}
		}
	}
	if module == nil {
		return develVersion
	}
	version := module.Version
	if module.Replace != nil {
		// A module replaced by a directory has no version: the code is
		// whatever the directory holds, not the version it replaces.
		version = module.Replace.Version
	}
	if version == "" || version == "(devel)" {
		return develVersion
	}
	return version
}

// protobomToolName is how protobom names itself as the tool that wrote a
// document, with its version.
func protobomToolName() string {
	return protospdx.ProtobomName + "-" + protobomVersion()
}

// isProtobomTool says whether a tool a document credits is protobom itself,
// as written by this or an earlier version, directly or after being read back
// from an SPDX document: "protobom" with a version, or a single name such as
// "protobom-v0.6.1" or "protobom-devel" that a reader could not split.
func isProtobomTool(name, version string) bool {
	if name == protospdx.ProtobomName {
		return true
	}
	rest, ok := strings.CutPrefix(name, protospdx.ProtobomName+"-")
	if !ok || version != "" || rest == "" {
		return false
	}
	if rest == develVersion || rest == "(devel)" {
		return true
	}
	rest = strings.TrimPrefix(rest, "v")
	return rest != "" && rest[0] >= '0' && rest[0] <= '9'
}
