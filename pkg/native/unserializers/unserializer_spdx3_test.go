// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package unserializers

import (
	"strings"
	"testing"
	"time"

	"github.com/carabiner-dev/spdx3/profiles/core"
	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/sbom"
)

// spdx3Doc wraps a graph in the envelope every SPDX 3 document has, so the
// tests below only have to say what is in the graph.
func spdx3Doc(graph string) string {
	return `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [` + graph + `]
	}`
}

// spdx3CreationInfo is the creation information the tests point their
// elements at. Every element in an SPDX 3 document has to have one.
const spdx3CreationInfo = `{
	"type": "CreationInfo",
	"@id": "_:creationinfo",
	"specVersion": "3.0.1",
	"created": "2026-08-07T12:30:45Z",
	"createdBy": ["https://spdx.org/rdf/3.0.1/terms/Core/SpdxOrganization"]
}`

func TestSPDX3UnserializeMetadata(t *testing.T) {
	t.Parallel()

	doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(spdx3CreationInfo+`,
		{
			"type": "SpdxDocument",
			"spdxId": "https://spdx.org/spdxdocs/protobom/test",
			"name": "a name",
			"comment": "a comment",
			"creationInfo": "_:creationinfo"
		}`)), nil, nil)
	require.NoError(t, err)

	// The document element is what protobom reads its metadata from, and
	// its identifier is the document's own.
	require.Equal(t, "https://spdx.org/spdxdocs/protobom/test", doc.Metadata.Id)
	require.Equal(t, "a name", doc.Metadata.Name)
	require.Equal(t, "a comment", doc.Metadata.Comment)
	require.Equal(t,
		time.Date(2026, 8, 7, 12, 30, 45, 0, time.UTC),
		doc.Metadata.Date.AsTime(),
	)

	// The graph itself is read in the steps that follow this one.
	require.NotNil(t, doc.NodeList)
	require.Empty(t, doc.NodeList.Nodes)
	require.Empty(t, doc.NodeList.Edges)
}

func TestSPDX3UnserializeRejects(t *testing.T) {
	t.Parallel()

	for name, graph := range map[string]string{
		// A document protobom cannot place: SPDX 3 allows a graph of loose
		// elements, but a bill of materials is always carried by a document.
		"a graph with no document element": spdx3CreationInfo,

		// A version this reader does not understand is refused rather than
		// read as though it were 3.0.1.
		"a later version": `{
			"type": "CreationInfo", "@id": "_:creationinfo",
			"specVersion": "3.1", "created": "2026-08-07T12:30:45Z",
			"createdBy": ["https://spdx.org/rdf/3.0.1/terms/Core/SpdxOrganization"]
		}, {
			"type": "SpdxDocument", "spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo"
		}`,

		// A document that says nothing about its version is not guessed at.
		"no version at all": `{
			"type": "CreationInfo", "@id": "_:creationinfo",
			"created": "2026-08-07T12:30:45Z",
			"createdBy": ["https://spdx.org/rdf/3.0.1/terms/Core/SpdxOrganization"]
		}, {
			"type": "SpdxDocument", "spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo"
		}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(graph)), nil, nil)
			require.Error(t, err)
		})
	}

	t.Run("a document whose context disagrees with itself", func(t *testing.T) {
		t.Parallel()
		data := `{
			"@context": "https://spdx.org/rdf/3.1/spdx-context.jsonld",
			"@graph": [` + spdx3CreationInfo + `, {
				"type": "SpdxDocument", "spdxId": "https://example.com/doc",
				"creationInfo": "_:creationinfo"
			}]
		}`
		_, err := NewSPDX3().Unserialize(strings.NewReader(data), nil, nil)
		require.ErrorContains(t, err, "@context")
	})

	t.Run("not JSON at all", func(t *testing.T) {
		t.Parallel()
		_, err := NewSPDX3().Unserialize(strings.NewReader("not a document"), nil, nil)
		require.Error(t, err)
	})
}

func TestSPDX3UnserializeElements(t *testing.T) {
	t.Parallel()

	doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(spdx3CreationInfo+`,
		{
			"type": "SpdxDocument",
			"spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo"
		},
		{
			"type": "software_Package",
			"spdxId": "https://example.com/doc#pkg-1",
			"creationInfo": "_:creationinfo",
			"name": "a package",
			"summary": "a summary",
			"description": "a description",
			"comment": "a comment",
			"software_packageVersion": "1.2.3",
			"software_downloadLocation": "https://example.com/pkg.tar.gz",
			"software_homePage": "https://example.com/",
			"software_sourceInfo": "built from source",
			"software_copyrightText": "Copyright someone",
			"software_attributionText": ["attributed to someone"],
			"software_packageUrl": "pkg:generic/a-package@1.2.3",
			"software_primaryPurpose": "library",
			"software_additionalPurpose": ["source", "diskImage"],
			"builtTime": "2026-08-01T00:00:00Z",
			"releaseTime": "2026-08-02T00:00:00Z",
			"validUntilTime": "2026-08-03T00:00:00Z",
			"verifiedUsing": [
				{"type": "Hash", "algorithm": "sha256", "hashValue": "abc123"},
				{"type": "Hash", "algorithm": "adler32", "hashValue": "nope"}
			],
			"externalIdentifier": [
				{"type": "ExternalIdentifier", "externalIdentifierType": "cpe23", "identifier": "cpe:2.3:a:x"},
				{"type": "ExternalIdentifier", "externalIdentifierType": "email", "identifier": "nope@example.com"}
			],
			"externalRef": [
				{"type": "ExternalRef", "externalRefType": "altWebPage", "locator": ["https://example.com/web"], "comment": "the site"}
			]
		},
		{
			"type": "software_File",
			"spdxId": "https://example.com/doc#file-1",
			"creationInfo": "_:creationinfo",
			"name": "a/file.txt",
			"contentType": "text/plain",
			"software_fileKind": "file",
			"software_contentIdentifier": [{
				"type": "software_ContentIdentifier",
				"software_contentIdentifierType": "gitoid",
				"software_contentIdentifierValue": "gitoid:blob:sha1:abc"
			}]
		}`)), nil, nil)
	require.NoError(t, err)
	require.Len(t, doc.NodeList.Nodes, 2)

	pkg := doc.NodeList.GetNodeByID("https://example.com/doc#pkg-1")
	require.NotNil(t, pkg)
	require.Equal(t, sbom.Node_PACKAGE, pkg.Type)
	require.Equal(t, "a package", pkg.Name)
	require.Equal(t, "a summary", pkg.Summary)
	require.Equal(t, "a description", pkg.Description)
	require.Equal(t, "a comment", pkg.Comment)
	require.Equal(t, "1.2.3", pkg.Version)
	require.Equal(t, "https://example.com/pkg.tar.gz", pkg.UrlDownload)
	require.Equal(t, "https://example.com/", pkg.UrlHome)
	require.Equal(t, "built from source", pkg.SourceInfo)
	require.Equal(t, "Copyright someone", pkg.Copyright)
	require.Equal(t, []string{"attributed to someone"}, pkg.Attribution)

	// The purpose SPDX 3 calls primary comes first, and one protobom has no
	// name for is dropped rather than turning into UNKNOWN_PURPOSE.
	require.Equal(t, []sbom.Purpose{sbom.Purpose_LIBRARY, sbom.Purpose_SOURCE}, pkg.PrimaryPurpose)

	require.Equal(t, "2026-08-01T00:00:00Z", pkg.BuildDate.AsTime().Format(time.RFC3339))
	require.Equal(t, "2026-08-02T00:00:00Z", pkg.ReleaseDate.AsTime().Format(time.RFC3339))
	require.Equal(t, "2026-08-03T00:00:00Z", pkg.ValidUntilDate.AsTime().Format(time.RFC3339))

	// An algorithm or identifier type protobom has no name for is dropped,
	// and does not displace the ones it does.
	require.Equal(t, map[int32]string{int32(sbom.HashAlgorithm_SHA256): "abc123"}, pkg.Hashes)
	require.Equal(t, map[int32]string{
		int32(sbom.SoftwareIdentifierType_PURL):  "pkg:generic/a-package@1.2.3",
		int32(sbom.SoftwareIdentifierType_CPE23): "cpe:2.3:a:x",
	}, pkg.Identifiers)

	require.Len(t, pkg.ExternalReferences, 1)
	require.Equal(t, "https://example.com/web", pkg.ExternalReferences[0].Url)
	require.Equal(t, sbom.ExternalReference_WEBSITE, pkg.ExternalReferences[0].Type)
	require.Equal(t, "the site", pkg.ExternalReferences[0].Comment)

	file := doc.NodeList.GetNodeByID("https://example.com/doc#file-1")
	require.NotNil(t, file)
	require.Equal(t, sbom.Node_FILE, file.Type)
	require.Equal(t, "a/file.txt", file.Name)
	require.Equal(t, "text/plain", file.ContentType)
	require.Equal(t, sbom.Node_FILE_KIND_FILE, file.FileKind)
	require.Equal(t, "gitoid:blob:sha1:abc",
		file.Identifiers[int32(sbom.SoftwareIdentifierType_GITOID)])
}

// TestSPDX3ElementsAreSelectedByClass is the test for the rule that keeps
// the reader honest. SPDX 3 puts AIPackage and DatasetPackage under Package,
// and Snippet under SoftwareArtifact, so a reader that asks what an element
// descends from ingests three classes protobom has no node for — as packages
// and files, silently, with their profile's data missing.
func TestSPDX3ElementsAreSelectedByClass(t *testing.T) {
	t.Parallel()

	doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(spdx3CreationInfo+`,
		{
			"type": "SpdxDocument",
			"spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo"
		},
		{
			"type": "software_Package",
			"spdxId": "https://example.com/doc#pkg",
			"creationInfo": "_:creationinfo",
			"name": "the one real package"
		},
		{
			"type": "ai_AIPackage",
			"spdxId": "https://example.com/doc#ai",
			"creationInfo": "_:creationinfo",
			"name": "an AI package"
		},
		{
			"type": "dataset_DatasetPackage",
			"spdxId": "https://example.com/doc#dataset",
			"creationInfo": "_:creationinfo",
			"name": "a dataset package"
		},
		{
			"type": "software_Snippet",
			"spdxId": "https://example.com/doc#snippet",
			"creationInfo": "_:creationinfo",
			"name": "a snippet"
		}`)), nil, nil)
	require.NoError(t, err)

	require.Len(t, doc.NodeList.Nodes, 1)
	require.Equal(t, "the one real package", doc.NodeList.Nodes[0].Name)
}

func TestSPDX3UnserializeRoots(t *testing.T) {
	t.Parallel()

	// A document says it is about a bill of materials, and the bill of
	// materials says it is about the software. Both hops have to be
	// followed, or the root is a collection protobom has no node for.
	t.Run("through the collections", func(t *testing.T) {
		t.Parallel()
		doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(spdx3CreationInfo+`,
			{
				"type": "SpdxDocument", "spdxId": "https://example.com/doc",
				"creationInfo": "_:creationinfo",
				"rootElement": ["https://example.com/doc#sbom"]
			},
			{
				"type": "software_Sbom", "spdxId": "https://example.com/doc#sbom",
				"creationInfo": "_:creationinfo",
				"rootElement": ["https://example.com/doc#pkg"]
			},
			{
				"type": "software_Package", "spdxId": "https://example.com/doc#pkg",
				"creationInfo": "_:creationinfo", "name": "a package"
			},
			{
				"type": "software_File", "spdxId": "https://example.com/doc#file",
				"creationInfo": "_:creationinfo", "name": "a file"
			}`)), nil, nil)
		require.NoError(t, err)
		require.Equal(t, []string{"https://example.com/doc#pkg"}, doc.NodeList.RootElements)
	})

	// A root that is not an element protobom reads names nothing: the AI
	// and dataset examples in the SPDX corpus are exactly this.
	t.Run("a root protobom has no node for", func(t *testing.T) {
		t.Parallel()
		doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(spdx3CreationInfo+`,
			{
				"type": "SpdxDocument", "spdxId": "https://example.com/doc",
				"creationInfo": "_:creationinfo",
				"rootElement": ["https://example.com/doc#sbom"]
			},
			{
				"type": "software_Sbom", "spdxId": "https://example.com/doc#sbom",
				"creationInfo": "_:creationinfo",
				"rootElement": ["https://example.com/doc#ai"]
			},
			{
				"type": "ai_AIPackage", "spdxId": "https://example.com/doc#ai",
				"creationInfo": "_:creationinfo", "name": "an AI package"
			}`)), nil, nil)
		require.NoError(t, err)
		require.Empty(t, doc.NodeList.RootElements)
	})

	// A collection that names itself is followed once rather than forever.
	t.Run("a collection naming itself", func(t *testing.T) {
		t.Parallel()
		doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(spdx3CreationInfo+`,
			{
				"type": "SpdxDocument", "spdxId": "https://example.com/doc",
				"creationInfo": "_:creationinfo",
				"rootElement": ["https://example.com/doc#sbom"]
			},
			{
				"type": "software_Sbom", "spdxId": "https://example.com/doc#sbom",
				"creationInfo": "_:creationinfo",
				"rootElement": [
					"https://example.com/doc#sbom",
					"https://example.com/doc#pkg"
				]
			},
			{
				"type": "software_Package", "spdxId": "https://example.com/doc#pkg",
				"creationInfo": "_:creationinfo", "name": "a package"
			}`)), nil, nil)
		require.NoError(t, err)
		require.Equal(t, []string{"https://example.com/doc#pkg"}, doc.NodeList.RootElements)
	})
}

// spdx3TwoPackages is a document with two packages to relate to each other,
// leaving the relationship itself to each test.
func spdx3TwoPackages(relationships string) string {
	return spdx3Doc(spdx3CreationInfo + `,
		{
			"type": "SpdxDocument", "spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo"
		},
		{
			"type": "software_Package", "spdxId": "https://example.com/doc#a",
			"creationInfo": "_:creationinfo", "name": "a"
		},
		{
			"type": "software_Package", "spdxId": "https://example.com/doc#b",
			"creationInfo": "_:creationinfo", "name": "b"
		},
		{
			"type": "software_Package", "spdxId": "https://example.com/doc#c",
			"creationInfo": "_:creationinfo", "name": "c"
		},` + relationships)
}

func spdx3Relationship(id, from, relType string, to ...string) string {
	quoted := make([]string, 0, len(to))
	for _, t := range to {
		quoted = append(quoted, `"`+t+`"`)
	}
	return `{
		"type": "Relationship", "spdxId": "https://example.com/doc#` + id + `",
		"creationInfo": "_:creationinfo",
		"from": "` + from + `",
		"relationshipType": "` + relType + `",
		"to": [` + strings.Join(quoted, ",") + `]
	}`
}

func TestSPDX3UnserializeRelationships(t *testing.T) {
	t.Parallel()

	const a, b, c = "https://example.com/doc#a", "https://example.com/doc#b", "https://example.com/doc#c"

	for name, tc := range map[string]struct {
		relationships string
		expected      []*sbom.Edge
	}{
		// SPDX 3 and protobom say this the same way round.
		"a relationship both say the same way": {
			spdx3Relationship("r", a, "contains", b),
			[]*sbom.Edge{{Type: sbom.Edge_contains, From: a, To: []string{b}}},
		},

		// Protobom has only "is a variant of", so the ends are swapped.
		"a relationship protobom states the other way round": {
			spdx3Relationship("r", a, "hasVariant", b),
			[]*sbom.Edge{{Type: sbom.Edge_variant, From: b, To: []string{a}}},
		},

		// Turning a relationship around fans it out: each target becomes the
		// source of an edge of its own.
		"turning a relationship around fans it out": {
			spdx3Relationship("r", a, "hasVariant", b, c),
			[]*sbom.Edge{
				{Type: sbom.Edge_variant, From: b, To: []string{a}},
				{Type: sbom.Edge_variant, From: c, To: []string{a}},
			},
		},

		// SPDX 3 renamed the ones it kept the direction of.
		"a renamed relationship": {
			spdx3Relationship("r", a, "hasDynamicLink", b),
			[]*sbom.Edge{{Type: sbom.Edge_dynamicLink, From: a, To: []string{b}}},
		},

		// Said twice, held once.
		"the same relationship stated twice": {
			spdx3Relationship("r1", a, "contains", b) + "," +
				spdx3Relationship("r2", a, "contains", b),
			[]*sbom.Edge{{Type: sbom.Edge_contains, From: a, To: []string{b}}},
		},

		// Two relationships of one type from one element are one edge.
		"two targets of the same type": {
			spdx3Relationship("r1", a, "contains", b) + "," +
				spdx3Relationship("r2", a, "contains", c),
			[]*sbom.Edge{{Type: sbom.Edge_contains, From: a, To: []string{b, c}}},
		},

		// A relationship belonging to a profile protobom does not model.
		"a security relationship": {
			spdx3Relationship("r", a, "hasAssociatedVulnerability", b),
			[]*sbom.Edge{},
		},

		// TODO(degradation): protobom names the period a tool is used in as
		// part of the relationship type, and the scope that would say which
		// is dropped, so there is no type left to read this as.
		"usesTool": {
			spdx3Relationship("r", a, "usesTool", b),
			[]*sbom.Edge{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			doc, err := NewSPDX3().Unserialize(
				strings.NewReader(spdx3TwoPackages(tc.relationships)), nil, nil)
			require.NoError(t, err)
			require.Equal(t, tc.expected, doc.NodeList.Edges)
		})
	}
}

// TestSPDX3RelationshipsNeedBothEnds is the rule that keeps the graph
// coherent. The elements this reader drops are named by relationships, and
// an edge to an element that is not there is worse than no edge at all.
func TestSPDX3RelationshipsNeedBothEnds(t *testing.T) {
	t.Parallel()

	doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(spdx3CreationInfo+`,
		{
			"type": "SpdxDocument", "spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo"
		},
		{
			"type": "software_Package", "spdxId": "https://example.com/doc#pkg",
			"creationInfo": "_:creationinfo", "name": "a package"
		},
		{
			"type": "software_Snippet", "spdxId": "https://example.com/doc#snippet",
			"creationInfo": "_:creationinfo", "name": "a snippet"
		},
		{
			"type": "software_File", "spdxId": "https://example.com/doc#file",
			"creationInfo": "_:creationinfo", "name": "a file"
		},`+
		// Pointing at a snippet, which protobom has no node for.
		spdx3Relationship("r1", "https://example.com/doc#pkg", "contains",
			"https://example.com/doc#snippet")+","+
		// Starting from one.
		spdx3Relationship("r2", "https://example.com/doc#snippet", "contains",
			"https://example.com/doc#file")+","+
		// Pointing at something that is not in the document at all.
		spdx3Relationship("r3", "https://example.com/doc#pkg", "contains",
			"https://example.com/doc#nowhere")+","+
		// One naming a snippet and a file: the file survives, the snippet
		// does not take the whole relationship down with it.
		spdx3Relationship("r4", "https://example.com/doc#pkg", "hasVariant",
			"https://example.com/doc#snippet", "https://example.com/doc#file"),
	)), nil, nil)
	require.NoError(t, err)

	require.Equal(t, []*sbom.Edge{{
		Type: sbom.Edge_variant,
		From: "https://example.com/doc#file",
		To:   []string{"https://example.com/doc#pkg"},
	}}, doc.NodeList.Edges)
}

// TestSPDX3DescribesFromACollection covers the other way a document says
// what it is about. Protobom has no node for the document element, so such a
// relationship has no edge to become and is read as a root instead.
func TestSPDX3DescribesFromACollection(t *testing.T) {
	t.Parallel()

	doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(spdx3CreationInfo+`,
		{
			"type": "SpdxDocument", "spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo",
			"rootElement": ["https://example.com/doc#sbom"]
		},
		{
			"type": "software_Sbom", "spdxId": "https://example.com/doc#sbom",
			"creationInfo": "_:creationinfo"
		},
		{
			"type": "software_Package", "spdxId": "https://example.com/doc#a",
			"creationInfo": "_:creationinfo", "name": "a"
		},
		{
			"type": "software_Package", "spdxId": "https://example.com/doc#b",
			"creationInfo": "_:creationinfo", "name": "b"
		},`+
		// The bill of materials says what it is about.
		spdx3Relationship("r1", "https://example.com/doc#sbom", "describes",
			"https://example.com/doc#a")+","+
		// A package describing another is an ordinary relationship.
		spdx3Relationship("r2", "https://example.com/doc#a", "describes",
			"https://example.com/doc#b"),
	)), nil, nil)
	require.NoError(t, err)

	require.Equal(t, []string{"https://example.com/doc#a"}, doc.NodeList.RootElements)
	require.Equal(t, []*sbom.Edge{{
		Type: sbom.Edge_describes,
		From: "https://example.com/doc#a",
		To:   []string{"https://example.com/doc#b"},
	}}, doc.NodeList.Edges)
}

// TestSPDX3LifecycleScopeIsDropped covers the decision that protobom holds
// no lifecycle scope: a scoped relationship is read as the relationship it
// is, without the period it holds during.
func TestSPDX3LifecycleScopeIsDropped(t *testing.T) {
	t.Parallel()

	doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3TwoPackages(`{
		"type": "LifecycleScopedRelationship",
		"spdxId": "https://example.com/doc#r",
		"creationInfo": "_:creationinfo",
		"from": "https://example.com/doc#a",
		"relationshipType": "dependsOn",
		"scope": "build",
		"to": ["https://example.com/doc#b"]
	}`)), nil, nil)
	require.NoError(t, err)

	require.Equal(t, []*sbom.Edge{{
		Type: sbom.Edge_dependsOn,
		From: "https://example.com/doc#a",
		To:   []string{"https://example.com/doc#b"},
	}}, doc.NodeList.Edges)
}

func TestSPDX3UnserializeCreators(t *testing.T) {
	t.Parallel()

	doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(`
		{
			"type": "CreationInfo", "@id": "_:creationinfo",
			"specVersion": "3.0.1", "created": "2026-08-07T12:30:45Z",
			"createdBy": [
				"https://example.com/doc#jane",
				"https://example.com/doc#acme",
				"https://example.com/doc#scanner",
				"https://spdx.org/rdf/3.0.1/terms/Core/SpdxOrganization"
			],
			"createdUsing": [
				"https://example.com/doc#tool-1",
				"https://example.com/doc#tool-2"
			]
		},
		{
			"type": "Person", "spdxId": "https://example.com/doc#jane",
			"creationInfo": "_:creationinfo", "name": "Jane",
			"externalIdentifier": [
				{"type": "ExternalIdentifier", "externalIdentifierType": "email", "identifier": "jane@example.com"},
				{"type": "ExternalIdentifier", "externalIdentifierType": "urlScheme", "identifier": "https://jane.example.com"}
			]
		},
		{
			"type": "Organization", "spdxId": "https://example.com/doc#acme",
			"creationInfo": "_:creationinfo", "name": "Acme"
		},
		{
			"type": "SoftwareAgent", "spdxId": "https://example.com/doc#scanner",
			"creationInfo": "_:creationinfo", "name": "a scanner"
		},
		{
			"type": "Tool", "spdxId": "https://example.com/doc#tool-1",
			"creationInfo": "_:creationinfo", "name": "protobom-v1.2.3"
		},
		{
			"type": "Tool", "spdxId": "https://example.com/doc#tool-2",
			"creationInfo": "_:creationinfo", "name": "spdx-maven-plugin"
		},
		{
			"type": "SpdxDocument", "spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo"
		}`)), nil, nil)
	require.NoError(t, err)

	// The three SPDX 3 agent classes become one protobom person each,
	// telling themselves apart by their flags. The predefined
	// SpdxOrganization is not an author: it is how a document says it will
	// not name one.
	require.Equal(t, []*sbom.Person{
		{Name: "Jane", Email: "jane@example.com", Url: "https://jane.example.com"},
		{Name: "Acme", IsOrg: true},
		{Name: "a scanner", IsSoftwareAgent: true},
	}, doc.Metadata.Authors)

	require.Equal(t, []*sbom.Tool{
		{Name: "protobom", Version: "v1.2.3"},
		{Name: "spdx-maven-plugin"},
	}, doc.Metadata.Tools)

	// None of them became a node.
	require.Empty(t, doc.NodeList.Nodes)
}

func TestSPDX3UnserializeSuppliersAndOriginators(t *testing.T) {
	t.Parallel()

	doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(spdx3CreationInfo+`,
		{
			"type": "SpdxDocument", "spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo"
		},
		{
			"type": "Organization", "spdxId": "https://example.com/doc#supplier",
			"creationInfo": "_:creationinfo", "name": "Supplier Inc"
		},
		{
			"type": "Person", "spdxId": "https://example.com/doc#author",
			"creationInfo": "_:creationinfo", "name": "An Author",
			"externalIdentifier": [
				{"type": "ExternalIdentifier", "externalIdentifierType": "email", "identifier": "author@example.com"}
			]
		},
		{
			"type": "software_Package", "spdxId": "https://example.com/doc#pkg",
			"creationInfo": "_:creationinfo", "name": "a package",
			"suppliedBy": "https://example.com/doc#supplier",
			"originatedBy": ["https://example.com/doc#author"]
		}`)), nil, nil)
	require.NoError(t, err)

	// The agents are read onto the package, not into the graph beside it.
	require.Len(t, doc.NodeList.Nodes, 1)
	pkg := doc.NodeList.Nodes[0]
	require.Equal(t, []*sbom.Person{{Name: "Supplier Inc", IsOrg: true}}, pkg.Suppliers)
	require.Equal(t, []*sbom.Person{
		{Name: "An Author", Email: "author@example.com"},
	}, pkg.Originators)
}

// TestSPDX3ToolNameSplit covers the answer to a question SPDX 3 leaves open:
// its Tool has a name and no version, so protobom's writer joins the two
// with a dash and the reader has to decide where to take them apart.
func TestSPDX3ToolNameSplit(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]*sbom.Tool{
		// What protobom writes, read back as it went out.
		"protobom-v1.2.3":          {Name: "protobom", Version: "v1.2.3"},
		"protobom-1.2.3":           {Name: "protobom", Version: "1.2.3"},
		"Microsoft.SBOMTool-0.2.7": {Name: "Microsoft.SBOMTool", Version: "0.2.7"},

		// Tools whose names simply contain dashes, all of them from the
		// SPDX examples corpus. Splitting these would invent versions.
		"spdx-maven-plugin":                    {Name: "spdx-maven-plugin"},
		"github.com/spdx/tools-golang/builder": {Name: "github.com/spdx/tools-golang/builder"},
		"Parlay":                               {Name: "Parlay"},
		"Source Auditor Open Source Console":   {Name: "Source Auditor Open Source Console"},

		// TODO(degradation): a version that does not start with a digit is
		// not one this can recognize, so it stays part of the name.
		"protobom-devel": {Name: "protobom-devel"},

		// Nothing to split on either side of the dash.
		"-1.2.3": {Name: "-1.2.3"},
		"tool-":  {Name: "tool-"},
		"":       {Name: ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tool, ok := toolFromSPDX3(core.NewTool("https://example.com/t", name))
			require.True(t, ok)
			require.Equal(t, want.Name, tool.Name)
			require.Equal(t, want.Version, tool.Version)
		})
	}
}
