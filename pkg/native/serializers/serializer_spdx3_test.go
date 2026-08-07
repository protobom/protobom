// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package serializers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	spdx3 "github.com/carabiner-dev/spdx3"
	"github.com/carabiner-dev/spdx3/profiles/core"
	"github.com/carabiner-dev/spdx3/profiles/software"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

func testDocument() *sbom.Document {
	return &sbom.Document{
		Metadata: &sbom.Metadata{
			Id:      "https://example.com/spdx/document",
			Name:    "test document",
			Date:    timestamppb.New(time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)),
			Tools:   []*sbom.Tool{{Name: "scanner", Version: "1.2.3"}},
			Authors: []*sbom.Person{{Name: "Alice", Email: "alice@example.com"}},
		},
		NodeList: &sbom.NodeList{
			RootElements: []string{"pkg-1"},
			Nodes: []*sbom.Node{
				{
					Id:               "pkg-1",
					Type:             sbom.Node_PACKAGE,
					Name:             "example-lib",
					Version:          "1.4.2",
					UrlDownload:      "https://example.com/example-lib-1.4.2.tar.gz",
					UrlHome:          "https://example.com/",
					LicenseConcluded: "Apache-2.0",
					Licenses:         []string{"Apache-2.0", "MIT"},
					Copyright:        "Copyright 2026 Example",
					PrimaryPurpose:   []sbom.Purpose{sbom.Purpose_LIBRARY, sbom.Purpose_SOURCE},
					Hashes:           map[int32]string{int32(sbom.HashAlgorithm_SHA256): "5d41402abc4b2a76b9719d911017c592f0e8b1b45c0f47b09fb8f0e2e0d9c0aa"},
					Identifiers:      map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): "pkg:generic/example-lib@1.4.2"},
					BuildDate:        timestamppb.New(time.Date(2026, 8, 1, 10, 30, 15, 123456789, time.UTC)),
					Suppliers:        []*sbom.Person{{Name: "Example Inc", IsOrg: true}},
				},
				{Id: "file-1", Type: sbom.Node_FILE, Name: "./src/main.go"},
			},
			Edges: []*sbom.Edge{
				{Type: sbom.Edge_contains, From: "pkg-1", To: []string{"file-1"}},
			},
		},
	}
}

// asSlice and asMap read a rendered document, failing the test rather than
// yielding a zero value when it is not shaped as expected.
func asSlice(t *testing.T, v any) []any {
	t.Helper()
	s, ok := v.([]any)
	require.True(t, ok, "expected a list, got %T", v)
	return s
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	require.True(t, ok, "expected an object, got %T", v)
	return m
}

func serialize(t *testing.T, bom *sbom.Document) (env *spdx3.Envelope, rendered map[string]any) {
	t.Helper()
	doc, err := (&SPDX3{}).Serialize(bom, &native.SerializeOptions{}, nil)
	require.NoError(t, err)
	env, ok := doc.(*spdx3.Envelope)
	require.True(t, ok)

	buf := &bytes.Buffer{}
	require.NoError(t, (&SPDX3{}).Render(env, buf, &native.RenderOptions{}, nil))

	rendered = map[string]any{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rendered))
	return env, rendered
}

// byType indexes the elements of a rendered document by their SPDX class.
func byType(t *testing.T, doc map[string]any) map[string][]map[string]any {
	t.Helper()
	elements := map[string][]map[string]any{}
	for _, raw := range asSlice(t, doc["@graph"]) {
		node := asMap(t, raw)
		class, ok := node["type"].(string)
		require.True(t, ok, "every element states its type")
		elements[class] = append(elements[class], node)
	}
	return elements
}

func TestSPDX3Serialize(t *testing.T) {
	_, rendered := serialize(t, testDocument())

	require.Equal(t, spdx3.ContextURL301, rendered["@context"])
	elements := byType(t, rendered)

	// The document names what it is about.
	require.Len(t, elements["SpdxDocument"], 1)
	document := elements["SpdxDocument"][0]
	require.Equal(t, "test document", document["name"])
	roots := asSlice(t, document["rootElement"])
	require.Len(t, roots, 1)
	require.Contains(t, roots[0], "pkg-1")

	// A document names its roots twice, as the tools that write SPDX 3 do:
	// with rootElement, and with one describes relationship per root.
	describes := []map[string]any{}
	for _, rel := range elements["Relationship"] {
		if rel["relationshipType"] == "describes" {
			describes = append(describes, rel)
		}
	}
	require.Len(t, describes, 1)
	require.Equal(t, document["spdxId"], describes[0]["from"])
	require.Contains(t, asSlice(t, describes[0]["to"])[0], "pkg-1")
	require.Len(t, asSlice(t, describes[0]["to"]), 1, "one relationship per root")

	// The collection names every element, the describes relationship too.
	listed := map[string]bool{}
	for _, e := range asSlice(t, document["element"]) {
		listed[fmt.Sprint(e)] = true
	}
	require.True(t, listed[fmt.Sprint(describes[0]["spdxId"])],
		"element[] is built after everything else, so it names the whole graph")

	// The package carries what the node said.
	require.Len(t, elements["software_Package"], 1)
	pkg := elements["software_Package"][0]
	require.Equal(t, "example-lib", pkg["name"])
	require.Equal(t, "1.4.2", pkg["software_packageVersion"])
	require.Equal(t, "https://example.com/example-lib-1.4.2.tar.gz", pkg["software_downloadLocation"])
	require.Equal(t, "https://example.com/", pkg["software_homePage"])
	require.Equal(t, "Copyright 2026 Example", pkg["software_copyrightText"])

	// The first purpose is the primary one and the rest are additional.
	require.Equal(t, "library", pkg["software_primaryPurpose"])
	require.Equal(t, []any{"source"}, pkg["software_additionalPurpose"])

	// A timestamp is written in the form SPDX asks for, whatever precision
	// the protobom carried.
	require.Equal(t, "2026-08-01T10:30:15Z", pkg["builtTime"])

	hashes := asSlice(t, pkg["verifiedUsing"])
	require.Len(t, hashes, 1)
	require.Equal(t, "sha256", asMap(t, hashes[0])["algorithm"])

	ids := asSlice(t, pkg["externalIdentifier"])
	require.Len(t, ids, 1)
	require.Equal(t, "packageUrl", asMap(t, ids[0])["externalIdentifierType"])

	require.Len(t, elements["software_File"], 1)

	// Licences are elements joined by a relationship, not fields.
	require.Len(t, elements["simplelicensing_LicenseExpression"], 2)

	// The creation information credits the author and the tools.
	require.Len(t, elements["CreationInfo"], 1)
	creation := elements["CreationInfo"][0]
	require.Equal(t, "2026-08-06T12:00:00Z", creation["created"])
	require.Equal(t, core.SpecVersion, creation["specVersion"])
	require.Len(t, creation["createdBy"], 1)
	require.Len(t, creation["createdUsing"], 2) // protobom itself, and the scanner
	require.Len(t, elements["Person"], 1)
	require.Equal(t, "Alice", elements["Person"][0]["name"])
	require.Len(t, elements["Organization"], 1) // the package's supplier
}

// The relationship vocabularies of SPDX 2 and 3 differ: most types were
// renamed, the inverse of nearly all of them was dropped, and the dependency
// and tool variants became a lifecycle scope.
func TestSPDX3EdgeMapping(t *testing.T) {
	for _, tc := range []struct {
		name     string
		edge     sbom.Edge_Type
		relType  string
		from, to string
		class    string
		scope    string
	}{
		{
			name: "same name and direction",
			edge: sbom.Edge_contains, relType: "contains", from: "a", to: "b",
			class: "Relationship",
		},
		{
			name: "renamed, same direction",
			edge: sbom.Edge_dynamicLink, relType: "hasDynamicLink", from: "a", to: "b",
			class: "Relationship",
		},
		{
			name: "an inverse SPDX 3 dropped is turned around",
			edge: sbom.Edge_contained_by, relType: "contains", from: "b", to: "a",
			class: "Relationship",
		},
		{
			name: "a dependency variant becomes a scope",
			edge: sbom.Edge_buildDependency, relType: "dependsOn", from: "b", to: "a",
			class: "LifecycleScopedRelationship", scope: "build",
		},
		{
			name: "a tool variant becomes usesTool and a scope",
			edge: sbom.Edge_testTool, relType: "usesTool", from: "b", to: "a",
			class: "LifecycleScopedRelationship", scope: "test",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bom := testDocument()
			bom.NodeList.Nodes[0].Id = "a"
			bom.NodeList.Nodes[1].Id = "b"
			bom.NodeList.RootElements = []string{"a"}
			bom.NodeList.Edges = []*sbom.Edge{{Type: tc.edge, From: "a", To: []string{"b"}}}

			_, rendered := serialize(t, bom)

			var found map[string]any
			for _, node := range byType(t, rendered)[tc.class] {
				if node["relationshipType"] == tc.relType {
					found = node
				}
			}
			require.NotNil(t, found, "no %s of type %q", tc.class, tc.relType)
			require.Contains(t, found["from"], "#"+tc.from)
			require.Contains(t, asSlice(t, found["to"])[0], "#"+tc.to)
			if tc.scope != "" {
				require.Equal(t, tc.scope, found["scope"])
			}
		})
	}
}

// An inverted edge naming several targets becomes one relationship per
// target, since in SPDX 3 each of them is the source.
func TestSPDX3InvertedEdgeFansOut(t *testing.T) {
	bom := testDocument()
	bom.NodeList.Nodes = append(bom.NodeList.Nodes,
		&sbom.Node{Id: "file-2", Type: sbom.Node_FILE, Name: "./src/other.go"})
	bom.NodeList.Edges = []*sbom.Edge{
		{Type: sbom.Edge_contained_by, From: "pkg-1", To: []string{"file-1", "file-2"}},
	}

	_, rendered := serialize(t, bom)

	contains := []map[string]any{}
	for _, node := range byType(t, rendered)["Relationship"] {
		if node["relationshipType"] == "contains" {
			contains = append(contains, node)
		}
	}
	require.Len(t, contains, 2)
	for _, rel := range contains {
		require.Contains(t, asSlice(t, rel["to"])[0], "#pkg-1")
	}
}

func TestSPDX3SerializeErrors(t *testing.T) {
	_, err := (&SPDX3{}).Serialize(nil, &native.SerializeOptions{}, nil)
	require.Error(t, err)

	_, err = (&SPDX3{}).Serialize(&sbom.Document{}, &native.SerializeOptions{}, nil)
	require.Error(t, err, "a document with no metadata cannot be serialized")

	require.Error(t, (&SPDX3{}).Render("not an envelope", &bytes.Buffer{}, &native.RenderOptions{}, nil))
}

// Elements keep their protobom identifier, resolved against the document
// namespace when it is not already a URI.
func TestSPDX3ElementIdentifiers(t *testing.T) {
	env, _ := serialize(t, testDocument())

	var pkg *software.Package
	for _, node := range env.Graph {
		if p, ok := node.(*software.Package); ok {
			pkg = p
		}
	}
	require.NotNil(t, pkg)
	require.Equal(t, "https://example.com/spdx/document#pkg-1", pkg.GetSPDXID())
}

// TestSPDX3EdgeMappingIsExhaustive guards the mapping table against protobom
// growing an edge type nobody maps. An edge the table does not know is not an
// error when serializing, it simply does not reach the document, so a new one
// would go missing from every SBOM this writes without anything saying so.
func TestSPDX3EdgeMappingIsExhaustive(t *testing.T) {
	for value, name := range sbom.Edge_Type_name {
		edge := sbom.Edge_Type(value)
		if edge == sbom.Edge_UNKNOWN {
			continue
		}

		mapping, ok := edgeTypeToSPDX3[edge]
		require.True(t, ok,
			"edge type %q has no entry in edgeTypeToSPDX3, so edges of that type "+
				"would be left out of the document", name)
		require.NotEmpty(t, mapping.relType,
			"edge type %q maps to no SPDX 3 relationship type", name)
		require.True(t, mapping.relType.IsValid(),
			"edge type %q maps to %q, which is not a member of the SPDX 3 "+
				"relationship vocabulary", name, mapping.relType)

		if mapping.scope != "" {
			require.True(t, mapping.scope.IsValid(),
				"edge type %q maps to lifecycle scope %q, which is not a member "+
					"of the SPDX 3 vocabulary", name, mapping.scope)
		}
	}
}
