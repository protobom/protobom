// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package serializers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	spdx3 "github.com/carabiner-dev/spdx3"
	"github.com/carabiner-dev/spdx3/profiles/core"
	"github.com/carabiner-dev/spdx3/profiles/software"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	protospdx "github.com/protobom/protobom/pkg/formats/spdx"
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
			DocumentTypes: []*sbom.DocumentType{
				{Type: sbom.DocumentType_BUILD.Enum()},
			},
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

	// SPDX 3 separates the document, which is the file, from the bill of
	// materials it carries. The document's root is the bill; the bill's roots
	// are the software.
	require.Len(t, elements["SpdxDocument"], 1)
	document := elements["SpdxDocument"][0]
	require.Equal(t, "test document", document["name"])

	require.Len(t, elements["software_Sbom"], 1)
	sbomElement := elements["software_Sbom"][0]

	roots := asSlice(t, document["rootElement"])
	require.Len(t, roots, 1)
	require.Equal(t, sbomElement["spdxId"], roots[0], "the document is about the bill of materials")

	sbomRoots := asSlice(t, sbomElement["rootElement"])
	require.Len(t, sbomRoots, 1)
	require.Contains(t, sbomRoots[0], "pkg-1", "the bill of materials is about the software")

	// What kind of bill it is belongs to the software, not to the file.
	require.Equal(t, []any{"build"}, sbomElement["software_sbomType"])

	// The document says what it is about twice, as the tools that write
	// SPDX 3 do: with rootElement, and with a describes relationship.
	describes := []map[string]any{}
	for _, rel := range elements["Relationship"] {
		if rel["relationshipType"] == "describes" {
			describes = append(describes, rel)
		}
	}
	require.Len(t, describes, 1)
	require.Equal(t, document["spdxId"], describes[0]["from"])
	require.Equal(t, sbomElement["spdxId"], asSlice(t, describes[0]["to"])[0])

	// The collection does not name its members unless asked to.
	require.Nil(t, document["element"])

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

// element is optional, the graph already carries every element, and naming
// them again roughly doubles the references, so it is written only on request.
func TestSPDX3ListCollectionElements(t *testing.T) {
	opts := DefaultSPDX3Options
	opts.ListCollectionElements = true

	doc, err := (&SPDX3{}).Serialize(testDocument(), &native.SerializeOptions{}, opts)
	require.NoError(t, err)
	env, ok := doc.(*spdx3.Envelope)
	require.True(t, ok)

	buf := &bytes.Buffer{}
	require.NoError(t, (&SPDX3{}).Render(env, buf, &native.RenderOptions{}, nil))
	rendered := map[string]any{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rendered))

	elements := byType(t, rendered)
	document := elements["SpdxDocument"][0]
	listed := asSlice(t, document["element"])
	require.NotEmpty(t, listed)

	// Everything but the document itself, including the relationships built
	// after it.
	names := map[string]bool{}
	for _, e := range listed {
		names[fmt.Sprint(e)] = true
	}
	require.False(t, names[fmt.Sprint(document["spdxId"])], "a collection is not its own member")
	for _, rel := range elements["Relationship"] {
		require.True(t, names[fmt.Sprint(rel["spdxId"])],
			"the list is built last, so it names the relationships too")
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

// serializeWith serializes and renders a document with the given options,
// returning the rendered bytes.
func serializeWith(t *testing.T, bom *sbom.Document, opts SPDX3Options) []byte {
	t.Helper()
	doc, err := (&SPDX3{}).Serialize(bom, &native.SerializeOptions{}, opts)
	require.NoError(t, err)
	buf := &bytes.Buffer{}
	require.NoError(t, (&SPDX3{}).Render(doc, buf, &native.RenderOptions{}, nil))
	return buf.Bytes()
}

// licenseTargets returns what the relationships of a type point at, as
// license expressions where they point at one and IRIs where they do not.
func licenseTargets(t *testing.T, rendered map[string]any, relType string) []string {
	t.Helper()
	elements := byType(t, rendered)
	expressions := map[string]string{}
	for _, license := range elements["simplelicensing_LicenseExpression"] {
		expressions[fmt.Sprint(license["spdxId"])] = fmt.Sprint(license["simplelicensing_licenseExpression"])
	}
	targets := []string{}
	for _, rel := range elements["Relationship"] {
		if rel["relationshipType"] != relType {
			continue
		}
		for _, to := range asSlice(t, rel["to"]) {
			id := fmt.Sprint(to)
			if expression, ok := expressions[id]; ok {
				id = expression
			}
			targets = append(targets, id)
		}
	}
	return targets
}

func TestSPDX3DeclaredLicenses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		licenses []string
		expected []string
	}{
		{"none", nil, []string{}},
		{"one", []string{"MIT"}, []string{"MIT"}},
		{"several are all declared", []string{"MIT", "Apache-2.0"}, []string{"MIT AND Apache-2.0"}},
		{
			"a compound entry is bracketed",
			[]string{"GPL-2.0-or-later OR LGPL-3.0-or-later", "MIT"},
			[]string{"(GPL-2.0-or-later OR LGPL-3.0-or-later) AND MIT"},
		},
		{"a single compound entry is kept", []string{"MIT OR Apache-2.0"}, []string{"MIT OR Apache-2.0"}},
		{"NONE is the predefined individual", []string{"NONE"}, []string{protospdx.SPDX3NoneLicenseIRI}},
		{"NOASSERTION is the predefined individual", []string{"NOASSERTION"}, []string{protospdx.SPDX3NoAssertionLicenseIRI}},
		{"NONE in lower case", []string{"none"}, []string{protospdx.SPDX3NoneLicenseIRI}},
		{"NOASSERTION in mixed case", []string{"NoAssertion"}, []string{protospdx.SPDX3NoAssertionLicenseIRI}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bom := testDocument()
			bom.NodeList.Nodes[0].LicenseConcluded = ""
			bom.NodeList.Nodes[0].Licenses = tc.licenses

			_, rendered := serialize(t, bom)
			require.Equal(t, tc.expected, licenseTargets(t, rendered, "hasDeclaredLicense"))
		})
	}
}

// Every node under the same license shares one license element, and NONE and
// NOASSERTION are the individuals the specification predefines, which are
// referenced rather than written out.
func TestSPDX3LicenseElementsAreShared(t *testing.T) {
	bom := testDocument()
	bom.NodeList.Nodes = []*sbom.Node{
		{Id: "a", Type: sbom.Node_PACKAGE, Name: "a", LicenseConcluded: "MIT", Licenses: []string{"MIT"}},
		{Id: "b", Type: sbom.Node_PACKAGE, Name: "b", LicenseConcluded: "MIT", Licenses: []string{"Apache-2.0"}},
		{Id: "c", Type: sbom.Node_FILE, Name: "c", LicenseConcluded: "NOASSERTION", Licenses: []string{"NONE"}},
		{Id: "d", Type: sbom.Node_FILE, Name: "d", LicenseConcluded: "NONE", Licenses: []string{"NOASSERTION"}},
	}
	bom.NodeList.RootElements = []string{"a"}
	bom.NodeList.Edges = nil

	_, rendered := serialize(t, bom)

	licenses := byType(t, rendered)["simplelicensing_LicenseExpression"]
	expressions := make([]string, 0, len(licenses))
	for _, license := range licenses {
		expressions = append(expressions, fmt.Sprint(license["simplelicensing_licenseExpression"]))
		require.Nil(t, license["simplelicensing_licenseListVersion"], "no version unless asked for")
	}
	require.Equal(t, []string{"MIT", "Apache-2.0"}, expressions)

	require.Equal(t, []string{
		"MIT", "MIT", protospdx.SPDX3NoAssertionLicenseIRI, protospdx.SPDX3NoneLicenseIRI,
	}, licenseTargets(t, rendered, "hasConcludedLicense"))
	require.Equal(t, []string{
		"MIT", "Apache-2.0", protospdx.SPDX3NoneLicenseIRI, protospdx.SPDX3NoAssertionLicenseIRI,
	}, licenseTargets(t, rendered, "hasDeclaredLicense"))
}

func TestSPDX3LicenseListVersion(t *testing.T) {
	for _, tc := range []struct {
		version, expected string
	}{
		{"3.27.0", "3.27.0"},
		{"3.27", "3.27.0"},
		{" 3.20 ", "3.20.0"},
		{"3.27.0-rc.1", "3.27.0-rc.1"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			opts := DefaultSPDX3Options
			opts.LicenseListVersion = tc.version

			rendered := map[string]any{}
			require.NoError(t, json.Unmarshal(serializeWith(t, testDocument(), opts), &rendered))

			licenses := byType(t, rendered)["simplelicensing_LicenseExpression"]
			require.NotEmpty(t, licenses)
			for _, license := range licenses {
				require.Equal(t, tc.expected, license["simplelicensing_licenseListVersion"])
			}
		})
	}
}

func TestSPDX3InvalidLicenseListVersion(t *testing.T) {
	for _, version := range []string{"3", "v3.27", "3.27.0.1", "03.27", "latest", "3.x"} {
		opts := DefaultSPDX3Options
		opts.LicenseListVersion = version
		_, err := (&SPDX3{}).Serialize(testDocument(), &native.SerializeOptions{}, opts)
		require.Error(t, err, version)
	}
}

// Writing the same document twice gives the same bytes, however the maps
// the hashes and identifiers are held in happen to be ordered.
func TestSPDX3OutputIsDeterministic(t *testing.T) {
	bom := testDocument()
	for _, node := range bom.NodeList.Nodes {
		node.Hashes = map[int32]string{
			int32(sbom.HashAlgorithm_SHA1):     "aa",
			int32(sbom.HashAlgorithm_SHA256):   "bb",
			int32(sbom.HashAlgorithm_SHA512):   "cc",
			int32(sbom.HashAlgorithm_MD5):      "dd",
			int32(sbom.HashAlgorithm_SHA384):   "ee",
			int32(sbom.HashAlgorithm_BLAKE3):   "ff",
			int32(sbom.HashAlgorithm_SHA3_256): "11",
		}
		node.Identifiers = map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL):   "pkg:generic/a@1",
			int32(sbom.SoftwareIdentifierType_CPE22):  "cpe:/a:example:a:1",
			int32(sbom.SoftwareIdentifierType_CPE23):  "cpe:2.3:a:example:a:1:*:*:*:*:*:*:*",
			int32(sbom.SoftwareIdentifierType_GITOID): "gitoid:blob:sha1:abc",
		}
	}

	first := serializeWith(t, bom, DefaultSPDX3Options)
	for range 20 {
		require.Equal(t, string(first), string(serializeWith(t, bom, DefaultSPDX3Options)))
	}

	// And in the order of their keys.
	_, rendered := serialize(t, bom)
	pkg := byType(t, rendered)["software_Package"][0]
	algorithms := []string{}
	for _, hash := range asSlice(t, pkg["verifiedUsing"]) {
		if algo, ok := asMap(t, hash)["algorithm"].(string); ok && asMap(t, hash)["type"] == "Hash" {
			algorithms = append(algorithms, algo)
		}
	}
	require.Equal(t, []string{"md5", "sha1", "sha256", "sha384", "sha512", "sha3_256", "blake3"}, algorithms)
}

func TestSPDX3CreationInfo(t *testing.T) {
	self := protobomToolName()

	for _, tc := range []struct {
		name      string
		authors   []*sbom.Person
		tools     []*sbom.Tool
		createdBy []string // "class:name"
		toolNames []string
	}{
		{
			name:      "no authors credits protobom",
			createdBy: []string{"SoftwareAgent:protobom"},
			toolNames: []string{self},
		},
		{
			name:      "authors are credited instead",
			authors:   []*sbom.Person{{Name: "Alice"}, {Name: "Acme", IsOrg: true}},
			createdBy: []string{"Person:Alice", "Organization:Acme"},
			toolNames: []string{self},
		},
		{
			name: "protobom read from an earlier document is not repeated",
			tools: []*sbom.Tool{
				{Name: "protobom", Version: "v0.6.1"},
				{Name: "protobom-v0.5.0"},
				{Name: "protobom-devel"},
				{Name: "scanner", Version: "1.0"},
				{Name: "protobom-storage", Version: "1.0"},
			},
			createdBy: []string{"SoftwareAgent:protobom"},
			toolNames: []string{self, "scanner-1.0", "protobom-storage-1.0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bom := testDocument()
			bom.Metadata.Authors = tc.authors
			bom.Metadata.Tools = tc.tools

			_, rendered := serialize(t, bom)
			elements := byType(t, rendered)

			names := map[string]string{}
			for class, nodes := range elements {
				for _, node := range nodes {
					names[fmt.Sprint(node["spdxId"])] = fmt.Sprintf("%s:%v", class, node["name"])
				}
			}

			creation := elements["CreationInfo"][0]
			creators := asSlice(t, creation["createdBy"])
			createdBy := make([]string, 0, len(creators))
			for _, id := range creators {
				require.NotEqual(t, core.SpdxOrganizationIRI, id, "the SPDX project did not create the document")
				createdBy = append(createdBy, names[fmt.Sprint(id)])
			}
			require.Equal(t, tc.createdBy, createdBy)

			used := asSlice(t, creation["createdUsing"])
			tools := make([]string, 0, len(used))
			for _, id := range used {
				tools = append(tools, strings.TrimPrefix(names[fmt.Sprint(id)], "Tool:"))
			}
			require.Equal(t, tc.toolNames, tools)
		})
	}
}

func TestProtobomVersionFromBuildInfo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		info     *debug.BuildInfo
		expected string
	}{
		{"no build info", nil, "devel"},
		{
			"protobom is the main module",
			&debug.BuildInfo{Main: debug.Module{Path: protobomModule, Version: "v0.7.0"}},
			"v0.7.0",
		},
		{
			"protobom built from a checkout",
			&debug.BuildInfo{Main: debug.Module{Path: protobomModule, Version: "(devel)"}},
			"devel",
		},
		{
			"protobom is a dependency",
			&debug.BuildInfo{
				Main: debug.Module{Path: "sigs.k8s.io/bom", Version: "v0.8.0"},
				Deps: []*debug.Module{
					{Path: "github.com/spdx/tools-golang", Version: "v0.5.7"},
					{Path: protobomModule, Version: "v0.6.1"},
				},
			},
			"v0.6.1",
		},
		{
			"protobom is replaced by another version",
			&debug.BuildInfo{
				Main: debug.Module{Path: "sigs.k8s.io/bom"},
				Deps: []*debug.Module{{
					Path: protobomModule, Version: "v0.6.1",
					Replace: &debug.Module{Path: "github.com/fork/protobom", Version: "v0.6.2"},
				}},
			},
			"v0.6.2",
		},
		{
			"protobom is replaced by a directory",
			&debug.BuildInfo{
				Main: debug.Module{Path: "sigs.k8s.io/bom"},
				Deps: []*debug.Module{{
					Path: protobomModule, Version: "v0.6.1",
					Replace: &debug.Module{Path: "../protobom"},
				}},
			},
			"devel",
		},
		{
			"protobom is not linked",
			&debug.BuildInfo{Main: debug.Module{Path: "example.com/tool", Version: "v1.0.0"}},
			"devel",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, protobomVersionFromBuildInfo(tc.info))
		})
	}
}

func TestIsProtobomTool(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, version string
		expected      bool
	}{
		{"protobom", "v0.6.1", true},
		{"protobom", "", true},
		{"protobom-v0.6.1", "", true},
		{"protobom-0.6.1", "", true},
		{"protobom-devel", "", true},
		{"protobom-(devel)", "", true},
		{"protobom-storage", "", false},
		{"protobom-validator", "", false},
		{"protobom-v0.6.1", "1.0", false},
		{"protobom-", "", false},
		{"scanner", "1.0", false},
	} {
		t.Run(tc.name+"@"+tc.version, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, isProtobomTool(tc.name, tc.version))
		})
	}
}

// A reference with no URL points nowhere, so it is not written.
func TestSPDX3SkipsEmptyExternalReferences(t *testing.T) {
	bom := testDocument()
	bom.NodeList.Nodes[0].ExternalReferences = []*sbom.ExternalReference{
		{Url: "", Type: sbom.ExternalReference_VCS},
		nil,
		{Url: "https://example.com/vcs", Type: sbom.ExternalReference_VCS},
	}

	_, rendered := serialize(t, bom)
	refs := asSlice(t, byType(t, rendered)["software_Package"][0]["externalRef"])
	require.Len(t, refs, 1)
	require.Equal(t, []any{"https://example.com/vcs"}, asMap(t, refs[0])["locator"])

	bom.NodeList.Nodes[0].ExternalReferences = []*sbom.ExternalReference{{Url: ""}}
	_, rendered = serialize(t, bom)
	require.Nil(t, byType(t, rendered)["software_Package"][0]["externalRef"])
}

// SPDX 3 replaced the SPDX 2 file types with a purpose and a media type.
func TestSPDX3FileTypes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fileTypes   []string
		purposes    []sbom.Purpose
		contentType string
		primary     any
		additional  any
		mediaType   any
	}{
		{name: "none"},
		{name: "source", fileTypes: []string{"SOURCE"}, primary: "source"},
		{
			name: "several purposes", fileTypes: []string{"ARCHIVE", "DOCUMENTATION"},
			primary: "archive", additional: []any{"documentation"},
		},
		{
			name: "the node's own purposes come first", fileTypes: []string{"SOURCE", "APPLICATION"},
			purposes: []sbom.Purpose{sbom.Purpose_APPLICATION}, primary: "application", additional: []any{"source"},
		},
		{name: "binary is a media type", fileTypes: []string{"BINARY"}, mediaType: "application/octet-stream"},
		{name: "text is a media type", fileTypes: []string{"TEXT", "OTHER"}, primary: "other", mediaType: "text/plain"},
		{
			name: "the node's own media type wins", fileTypes: []string{"BINARY"},
			contentType: "application/x-executable", mediaType: "application/x-executable",
		},
		{
			name: "a node media type that is not one is skipped", fileTypes: []string{"BINARY"},
			contentType: "executable", mediaType: "application/octet-stream",
		},
		{name: "a malformed media type is not written", contentType: "application/x/y"},
		{name: "lower case", fileTypes: []string{"source"}, primary: "source"},
		{name: "not carried over", fileTypes: []string{"IMAGE", "AUDIO", "VIDEO", "SPDX"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bom := testDocument()
			file := bom.NodeList.Nodes[1]
			file.FileTypes = tc.fileTypes
			file.PrimaryPurpose = tc.purposes
			file.ContentType = tc.contentType

			_, rendered := serialize(t, bom)
			written := byType(t, rendered)["software_File"][0]
			require.Equal(t, tc.primary, written["software_primaryPurpose"])
			require.Equal(t, tc.additional, written["software_additionalPurpose"])
			require.Equal(t, tc.mediaType, written["contentType"])
		})
	}
}
