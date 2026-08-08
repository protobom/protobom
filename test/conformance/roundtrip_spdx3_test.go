// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// TestRoundTripSPDX3Elements writes a document exercising every element
// field the SPDX 3 mapping covers and reads it back.
//
// The two directions are separate tables, one in the serializer and one in
// the reader, and nothing but this stops them drifting apart: a purpose or a
// reference type renamed on one side only would go on producing valid
// documents that quietly lose the field.
//
// Identifiers are written as IRIs under the document's own namespace so they
// survive unchanged, which keeps this about the fields rather than about how
// protobom identifiers become SPDX ones.
func TestRoundTripSPDX3Elements(t *testing.T) {
	const ns = "https://example.com/spdxdocs/roundtrip"

	built := timestamppb.New(mustTime(t, "2026-08-01T10:00:00Z"))
	released := timestamppb.New(mustTime(t, "2026-08-02T10:00:00Z"))
	validUntil := timestamppb.New(mustTime(t, "2026-08-03T10:00:00Z"))

	pkg := &sbom.Node{
		Id:             ns + "#pkg-1",
		Type:           sbom.Node_PACKAGE,
		Name:           "a package",
		Version:        "1.2.3",
		Summary:        "a summary",
		Description:    "a description",
		Comment:        "a comment",
		UrlDownload:    "https://example.com/pkg.tar.gz",
		UrlHome:        "https://example.com/",
		SourceInfo:     "built from source",
		Copyright:      "Copyright someone",
		Attribution:    []string{"attributed to someone"},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY, sbom.Purpose_SOURCE},
		BuildDate:      built,
		ReleaseDate:    released,
		ValidUntilDate: validUntil,
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): "0123456789abcdef",
			int32(sbom.HashAlgorithm_SHA512): "fedcba9876543210",
		},
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL):  "pkg:generic/a-package@1.2.3",
			int32(sbom.SoftwareIdentifierType_CPE23): "cpe:2.3:a:example:a-package:1.2.3:*:*:*:*:*:*:*",
		},
		ExternalReferences: []*sbom.ExternalReference{
			{Url: "https://example.com/web", Type: sbom.ExternalReference_WEBSITE, Comment: "the site"},
			{Url: "https://example.com/issues", Type: sbom.ExternalReference_ISSUE_TRACKER},
			{Url: "https://example.com/vcs", Type: sbom.ExternalReference_VCS},
		},
	}

	file := &sbom.Node{
		Id:          ns + "#file-1",
		Type:        sbom.Node_FILE,
		Name:        "a/file.txt",
		Comment:     "a file comment",
		Copyright:   "Copyright someone else",
		Attribution: []string{"attributed elsewhere"},
		Hashes:      map[int32]string{int32(sbom.HashAlgorithm_SHA1): "abcdef0123456789"},
		Identifiers: map[int32]string{},
	}

	original := &sbom.Document{
		Metadata: &sbom.Metadata{Id: ns, Name: "a round trip", Version: "1"},
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{pkg, file},
			Edges:        []*sbom.Edge{},
			RootElements: []string{pkg.Id},
		},
	}

	var out bytes.Buffer
	require.NoError(t, writer.New().WriteStreamWithOptions(
		original, &out, &writer.Options{Format: formats.SPDX3JSON},
	))

	got, err := reader.New().ParseStreamWithOptions(
		bytes.NewReader(out.Bytes()),
		&reader.Options{
			Format:             formats.SPDX3JSON,
			UnserializeOptions: &native.UnserializeOptions{},
		},
	)
	require.NoError(t, err)

	require.Equal(t, ns, got.Metadata.Id)
	require.Equal(t, "a round trip", got.Metadata.Name)

	// The document says it is about the package, through the bill of
	// materials the writer wraps it in.
	require.Equal(t, []string{pkg.Id}, got.NodeList.RootElements)

	require.Len(t, got.NodeList.Nodes, 2)

	gotPkg := got.NodeList.GetNodeByID(pkg.Id)
	require.NotNil(t, gotPkg)
	for _, f := range []struct {
		name       string
		want, have any
	}{
		{"type", pkg.Type, gotPkg.Type},
		{"name", pkg.Name, gotPkg.Name},
		{"version", pkg.Version, gotPkg.Version},
		{"summary", pkg.Summary, gotPkg.Summary},
		{"description", pkg.Description, gotPkg.Description},
		{"comment", pkg.Comment, gotPkg.Comment},
		{"download url", pkg.UrlDownload, gotPkg.UrlDownload},
		{"home url", pkg.UrlHome, gotPkg.UrlHome},
		{"source info", pkg.SourceInfo, gotPkg.SourceInfo},
		{"copyright", pkg.Copyright, gotPkg.Copyright},
		{"attribution", pkg.Attribution, gotPkg.Attribution},
		{"purposes", pkg.PrimaryPurpose, gotPkg.PrimaryPurpose},
		{"hashes", pkg.Hashes, gotPkg.Hashes},
		{"identifiers", pkg.Identifiers, gotPkg.Identifiers},
	} {
		require.Equal(t, f.want, f.have, "package %s", f.name)
	}
	require.Equal(t, built.AsTime(), gotPkg.BuildDate.AsTime())
	require.Equal(t, released.AsTime(), gotPkg.ReleaseDate.AsTime())
	require.Equal(t, validUntil.AsTime(), gotPkg.ValidUntilDate.AsTime())

	// External references keep their type, URL and comment, whatever order
	// the document lists them in.
	refs := map[string]*sbom.ExternalReference{}
	for _, r := range gotPkg.ExternalReferences {
		refs[r.Url] = r
	}
	require.Len(t, refs, len(pkg.ExternalReferences))
	for _, want := range pkg.ExternalReferences {
		have, ok := refs[want.Url]
		require.True(t, ok, "reference to %s was lost", want.Url)
		require.Equal(t, want.Type, have.Type, "reference to %s", want.Url)
		require.Equal(t, want.Comment, have.Comment, "reference to %s", want.Url)
	}

	gotFile := got.NodeList.GetNodeByID(file.Id)
	require.NotNil(t, gotFile)
	require.Equal(t, sbom.Node_FILE, gotFile.Type)
	require.Equal(t, file.Name, gotFile.Name)
	require.Equal(t, file.Comment, gotFile.Comment)
	require.Equal(t, file.Copyright, gotFile.Copyright)
	require.Equal(t, file.Attribution, gotFile.Attribution)
	require.Equal(t, file.Hashes, gotFile.Hashes)
}

// vocabularyNS is the namespace TestRoundTripSPDX3EveryVocabulary writes
// its one-node documents under.
const vocabularyNS = "https://example.com/spdxdocs/vocabularies"

// TestRoundTripSPDX3EveryVocabulary walks every value of the vocabularies the
// element mapping covers, so a name that only one side knows is caught here
// rather than in a document that quietly lost a field.
func TestRoundTripSPDX3EveryVocabulary(t *testing.T) {
	// Purposes protobom writes as an SPDX 3 purpose that names something
	// else: SPDX 3 has deviceDriver and platform, but the writer sends them
	// to device and other, and a machine learning model to model.
	lossy := map[sbom.Purpose]bool{
		sbom.Purpose_DEVICE_DRIVER:          true,
		sbom.Purpose_PLATFORM:               true,
		sbom.Purpose_MACHINE_LEARNING_MODEL: true,
	}

	t.Run("purposes", func(t *testing.T) {
		for value, name := range sbom.Purpose_name {
			purpose := sbom.Purpose(value)
			if purpose == sbom.Purpose_UNKNOWN_PURPOSE || lossy[purpose] {
				continue
			}
			t.Run(name, func(t *testing.T) {
				got := roundTripNode(t, &sbom.Node{
					Id: vocabularyNS + "#n", Type: sbom.Node_PACKAGE, Name: "n",
					PrimaryPurpose: []sbom.Purpose{purpose},
					Identifiers:    map[int32]string{}, Hashes: map[int32]string{},
				})
				require.Equal(t, []sbom.Purpose{purpose}, got.PrimaryPurpose)
			})
		}
	})

	// Reference types SPDX 3 has no name for. The writer sends each of them
	// to "other", so they cannot come back as themselves. Sixteen of
	// protobom's sixty-one, most of them CycloneDX ideas SPDX has no word
	// for; the list is here so that a type leaving the named set is a test
	// failure rather than a silent loss.
	unnamed := map[sbom.ExternalReference_ExternalReferenceType]bool{
		sbom.ExternalReference_UNKNOWN:                 true,
		sbom.ExternalReference_ATTESTATION:             true,
		sbom.ExternalReference_BOM:                     true,
		sbom.ExternalReference_CODIFIED_INFRASTRUCTURE: true,
		sbom.ExternalReference_CONFIGURATION:           true,
		sbom.ExternalReference_DISTRIBUTION_INTAKE:     true,
		sbom.ExternalReference_EVIDENCE:                true,
		sbom.ExternalReference_FORMULATION:             true,
		sbom.ExternalReference_LOG:                     true,
		sbom.ExternalReference_MATURITY_REPORT:         true,
		sbom.ExternalReference_MODEL_CARD:              true,
		sbom.ExternalReference_POAM:                    true,
		sbom.ExternalReference_QUALITY_METRICS:         true,
		sbom.ExternalReference_SECURITY_CONTACT:        true,
		sbom.ExternalReference_SECURITY_SWID:           true,
		sbom.ExternalReference_VULNERABILITY_ASSERTION: true,
	}

	t.Run("external reference types", func(t *testing.T) {
		for value, name := range sbom.ExternalReference_ExternalReferenceType_name {
			refType := sbom.ExternalReference_ExternalReferenceType(value)
			t.Run(name, func(t *testing.T) {
				got := roundTripNode(t, &sbom.Node{
					Id: vocabularyNS + "#n", Type: sbom.Node_PACKAGE, Name: "n",
					ExternalReferences: []*sbom.ExternalReference{
						{Url: "https://example.com/x", Type: refType},
					},
					Identifiers: map[int32]string{}, Hashes: map[int32]string{},
				})
				require.Len(t, got.ExternalReferences, 1)
				if unnamed[refType] {
					// The reference itself survives; only its type is
					// coarsened, which is what "other" is for.
					require.Equal(t, sbom.ExternalReference_OTHER, got.ExternalReferences[0].Type)
					return
				}
				require.Equal(t, refType, got.ExternalReferences[0].Type)
			})
		}
	})

	t.Run("hash algorithms", func(t *testing.T) {
		for value, name := range sbom.HashAlgorithm_name {
			algo := sbom.HashAlgorithm(value)
			if algo.ToSPDX3() == "" {
				continue
			}
			t.Run(name, func(t *testing.T) {
				got := roundTripNode(t, &sbom.Node{
					Id: vocabularyNS + "#n", Type: sbom.Node_PACKAGE, Name: "n",
					Hashes:      map[int32]string{value: "abc123"},
					Identifiers: map[int32]string{},
				})
				require.Equal(t, map[int32]string{value: "abc123"}, got.Hashes)
			})
		}
	})

	t.Run("identifier types", func(t *testing.T) {
		for value, name := range sbom.SoftwareIdentifierType_name {
			idType := sbom.SoftwareIdentifierType(value)
			if idType == sbom.SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE {
				continue
			}
			t.Run(name, func(t *testing.T) {
				got := roundTripNode(t, &sbom.Node{
					Id: vocabularyNS + "#n", Type: sbom.Node_PACKAGE, Name: "n",
					Identifiers: map[int32]string{value: "an-identifier"},
					Hashes:      map[int32]string{},
				})
				require.Equal(t, "an-identifier", got.Identifiers[value])
			})
		}
	})
}

// roundTripNode writes a one-node document as SPDX 3, reads it back and
// returns the node.
func roundTripNode(t *testing.T, node *sbom.Node) *sbom.Node {
	t.Helper()

	var out bytes.Buffer
	require.NoError(t, writer.New().WriteStreamWithOptions(
		&sbom.Document{
			Metadata: &sbom.Metadata{Id: vocabularyNS},
			NodeList: &sbom.NodeList{
				Nodes: []*sbom.Node{node}, Edges: []*sbom.Edge{},
				RootElements: []string{node.Id},
			},
		},
		&out, &writer.Options{Format: formats.SPDX3JSON},
	))

	got, err := reader.New().ParseStreamWithOptions(
		bytes.NewReader(out.Bytes()),
		&reader.Options{
			Format:             formats.SPDX3JSON,
			UnserializeOptions: &native.UnserializeOptions{},
		},
	)
	require.NoError(t, err)

	read := got.NodeList.GetNodeByID(node.Id)
	require.NotNil(t, read, "the node did not survive the round trip")
	return read
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	require.NoError(t, err)
	return parsed
}

// TestRoundTripSPDX3EveryEdgeType walks every protobom relationship type
// through SPDX 3 and back.
//
// The two tables are each other's inverse only where SPDX 3 kept both
// directions of a relationship, which it mostly did not: it deleted every
// inverse type, so twenty of protobom's are written turned around and have
// to come back turned around again. Where protobom has both directions of a
// relationship and SPDX 3 only one, the pair collapses onto the forward one.
func TestRoundTripSPDX3EveryEdgeType(t *testing.T) {
	const ns = "https://example.com/spdxdocs/edges"
	const from, to = ns + "#a", ns + "#b"

	// Protobom says these two ways round what SPDX 3 says one way, so the
	// "... of" form is read back as the form that points the other way,
	// with its ends swapped to match. Nothing is lost: "a is contained by
	// b" and "b contains a" are the same statement.
	collapses := map[sbom.Edge_Type]sbom.Edge_Type{
		sbom.Edge_contained_by:    sbom.Edge_contains,
		sbom.Edge_dependencyOf:    sbom.Edge_dependsOn,
		sbom.Edge_describedBy:     sbom.Edge_describes,
		sbom.Edge_generatedFrom:   sbom.Edge_generates,
		sbom.Edge_prerequisiteFor: sbom.Edge_prerequisite,
	}

	// The relationship types protobom states with a lifecycle scope. SPDX 3
	// writes the scope on the relationship, the reader drops it, and what is
	// left is the type that names no period — or, for the tool ones,
	// nothing at all, since protobom has no way to say a tool is used
	// without saying when.
	scoped := map[sbom.Edge_Type]sbom.Edge_Type{
		sbom.Edge_buildDependency:   sbom.Edge_dependsOn,
		sbom.Edge_devDependency:     sbom.Edge_dependsOn,
		sbom.Edge_runtimeDependency: sbom.Edge_dependsOn,
		sbom.Edge_testDependency:    sbom.Edge_dependsOn,
		sbom.Edge_buildTool:         sbom.Edge_UNKNOWN,
		sbom.Edge_devTool:           sbom.Edge_UNKNOWN,
		sbom.Edge_testTool:          sbom.Edge_UNKNOWN,
	}

	for value, name := range sbom.Edge_Type_name {
		edgeType := sbom.Edge_Type(value)
		if edgeType == sbom.Edge_UNKNOWN {
			continue
		}

		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, writer.New().WriteStreamWithOptions(
				&sbom.Document{
					Metadata: &sbom.Metadata{Id: ns},
					NodeList: &sbom.NodeList{
						Nodes: []*sbom.Node{
							{Id: from, Type: sbom.Node_PACKAGE, Name: "a", Identifiers: map[int32]string{}, Hashes: map[int32]string{}},
							{Id: to, Type: sbom.Node_PACKAGE, Name: "b", Identifiers: map[int32]string{}, Hashes: map[int32]string{}},
						},
						Edges:        []*sbom.Edge{{Type: edgeType, From: from, To: []string{to}}},
						RootElements: []string{from},
					},
				},
				&out, &writer.Options{Format: formats.SPDX3JSON},
			))

			got, err := reader.New().ParseStreamWithOptions(
				bytes.NewReader(out.Bytes()),
				&reader.Options{
					Format:             formats.SPDX3JSON,
					UnserializeOptions: &native.UnserializeOptions{},
				},
			)
			require.NoError(t, err)

			// A type that loses its "... of" reads back as the type that
			// points the other way, so its ends swap to keep the statement
			// the same.
			want, wantFrom, wantTo := edgeType, from, to
			if collapsed, ok := collapses[edgeType]; ok {
				want, wantFrom, wantTo = collapsed, to, from
			}
			if unscoped, ok := scoped[edgeType]; ok {
				want, wantFrom, wantTo = unscoped, to, from
			}

			if want == sbom.Edge_UNKNOWN {
				require.Empty(t, got.NodeList.Edges,
					"%s has no way back, so it should leave no edge behind", name)
				return
			}

			require.Len(t, got.NodeList.Edges, 1, "%s did not survive the round trip", name)
			edge := got.NodeList.Edges[0]
			require.Equal(t, want, edge.Type, "%s came back as the wrong type", name)
			require.Equal(t, wantFrom, edge.From, "%s relates the wrong elements", name)
			require.Equal(t, []string{wantTo}, edge.To, "%s relates the wrong elements", name)
		})
	}
}
