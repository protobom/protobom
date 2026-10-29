// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

// This program regenerates the SPDX License List data embedded in the
// licenselist package from the release of the spdx/license-list-data
// repository pinned in the package's VERSION file.
//
// It is run through make:
//
//	make licenselist
//
// or directly, pointing it to the package directory:
//
//	go run ./pkg/licenselist/generate pkg/licenselist
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	versionFile = "VERSION"
	outputFile  = "data_gen.go"
	baseURL     = "https://raw.githubusercontent.com/spdx/license-list-data/%s/json/%s.json"
)

// tagPattern is the form of the release tags of spdx/license-list-data.
var tagPattern = regexp.MustCompile(`^v(\d+\.\d+\.\d+)$`)

type licenseList struct {
	Version  string `json:"licenseListVersion"`
	Licenses []struct {
		ID         string `json:"licenseId"`
		Deprecated bool   `json:"isDeprecatedLicenseId"`
	} `json:"licenses"`
}

type exceptionList struct {
	Version    string `json:"licenseListVersion"`
	Exceptions []struct {
		ID         string `json:"licenseExceptionId"`
		Deprecated bool   `json:"isDeprecatedLicenseId"`
	} `json:"exceptions"`
}

type entry struct {
	ID         string
	Deprecated bool
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: generate <licenselist package dir>")
		os.Exit(1)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, versionFile)) //nolint:gosec // dir is the developer's command line argument
	if err != nil {
		return fmt.Errorf("reading pinned version: %w", err)
	}
	tag := strings.TrimSpace(string(raw))
	m := tagPattern.FindStringSubmatch(tag)
	if m == nil {
		return fmt.Errorf("pinned version %q is not a release tag (vX.Y.Z)", tag)
	}
	version := m[1]

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var ll licenseList
	if err := fetchJSON(ctx, fmt.Sprintf(baseURL, tag, "licenses"), &ll); err != nil {
		return err
	}
	var el exceptionList
	if err := fetchJSON(ctx, fmt.Sprintf(baseURL, tag, "exceptions"), &el); err != nil {
		return err
	}
	for _, got := range []string{ll.Version, el.Version} {
		if got != version {
			return fmt.Errorf("release %s publishes license list version %q, expected %q", tag, got, version)
		}
	}

	licenses := make([]entry, 0, len(ll.Licenses))
	for _, l := range ll.Licenses {
		licenses = append(licenses, entry{ID: l.ID, Deprecated: l.Deprecated})
	}
	exceptions := make([]entry, 0, len(el.Exceptions))
	for _, e := range el.Exceptions {
		exceptions = append(exceptions, entry{ID: e.ID, Deprecated: e.Deprecated})
	}

	src, err := render(version, licenses, exceptions)
	if err != nil {
		return err
	}
	out := filepath.Join(dir, outputFile)
	if err := os.WriteFile(out, src, 0o644); err != nil { //nolint:gosec // generated source, world readable like the rest
		return fmt.Errorf("writing %s: %w", out, err)
	}
	fmt.Printf("wrote %s: license list %s, %d licenses, %d exceptions\n", out, version, len(licenses), len(exceptions))
	return nil
}

func fetchJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // url is built from a validated release tag
	if err != nil {
		return fmt.Errorf("building request for %s: %w", url, err)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // see above
	if err != nil {
		return fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading %s: %w", url, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing %s: %w", url, err)
	}
	return nil
}

// render writes the Go source of the data file. Entries are sorted without
// regard to case so the output is stable across releases that only add.
func render(version string, licenses, exceptions []entry) ([]byte, error) {
	sortEntries(licenses)
	sortEntries(exceptions)

	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors\n")
	fmt.Fprintf(&b, "// SPDX-License-Identifier: Apache-2.0\n\n")
	fmt.Fprintf(&b, "// Code generated from spdx/license-list-data v%s by generate/main.go. DO NOT EDIT.\n\n", version)
	fmt.Fprintf(&b, "package licenselist\n\n")
	fmt.Fprintf(&b, "// Version is the version of the SPDX License List this data comes from.\n")
	fmt.Fprintf(&b, "const Version = %q\n\n", version)
	writeEntries(&b, "licenses", "licenses are the listed license identifiers.", licenses)
	writeEntries(&b, "exceptions", "exceptions are the listed license exception identifiers.", exceptions)

	src, err := format.Source(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("formatting generated source: %w", err)
	}
	return src, nil
}

func writeEntries(b *bytes.Buffer, name, doc string, entries []entry) {
	fmt.Fprintf(b, "// %s\n", doc)
	fmt.Fprintf(b, "var %s = []entry{\n", name)
	for _, e := range entries {
		if e.Deprecated {
			fmt.Fprintf(b, "\t{ID: %q, Deprecated: true},\n", e.ID)
		} else {
			fmt.Fprintf(b, "\t{ID: %q},\n", e.ID)
		}
	}
	fmt.Fprintf(b, "}\n\n")
}

func sortEntries(entries []entry) {
	sort.Slice(entries, func(i, j int) bool {
		a, b := strings.ToLower(entries[i].ID), strings.ToLower(entries[j].ID)
		if a != b {
			return a < b
		}
		return entries[i].ID < entries[j].ID
	})
}
