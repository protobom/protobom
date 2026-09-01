// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"fmt"
	"sort"
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

// The synthetic CycloneDX round trip suite mirrors the SPDX 3 one: protobom
// documents built to exercise every value the CycloneDX mapping covers are
// written out and read back, pinning what survives and what degrades as an
// explicit contract. The two directions are separate tables in the
// serializer and the unserializer, and nothing but this stops them from
// drifting apart.
//
// The walks run on CycloneDX 1.6, where every vocabulary value the mapping
// knows has a schema home.

// cdxRoundTrip writes the document as CycloneDX 1.6 and reads it back.
func cdxRoundTrip(t *testing.T, doc *sbom.Document) *sbom.Document {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, writer.New().WriteStreamWithOptions(
		doc, &buf, &writer.Options{
			Format:        formats.CDX16JSON,
			RenderOptions: &native.RenderOptions{Indent: 2},
		},
	))

	reread, err := reader.New().ParseStream(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	return reread
}

// cdxOneNodeDoc wraps a single node in a document for the vocabulary walks.
func cdxOneNodeDoc(node *sbom.Node) *sbom.Document {
	return &sbom.Document{
		Metadata: &sbom.Metadata{Id: "urn:uuid:11111111-2222-3333-4444-555555555555"},
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{node},
			Edges:        []*sbom.Edge{},
			RootElements: []string{node.Id},
		},
	}
}

// TestRoundTripCDXElements writes a document exercising every node and
// metadata field the CycloneDX mapping covers and reads it back.
func TestRoundTripCDXElements(t *testing.T) {
	date := timestamppb.New(time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC))
	docType := sbom.DocumentType_BUILD

	pkg := &sbom.Node{
		Id:               "pkg-1",
		Type:             sbom.Node_PACKAGE,
		Name:             "a package",
		Version:          "1.2.3",
		Description:      "a description",
		Copyright:        "Copyright someone",
		Licenses:         []string{"Apache-2.0"},
		LicenseConcluded: "Apache-2.0",
		PrimaryPurpose:   []sbom.Purpose{sbom.Purpose_LIBRARY},
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): "0123456789abcdef",
			int32(sbom.HashAlgorithm_SHA512): "fedcba9876543210",
		},
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL):  "pkg:generic/a-package@1.2.3",
			int32(sbom.SoftwareIdentifierType_CPE23): "cpe:2.3:a:example:a-package:1.2.3:*:*:*:*:*:*:*",
		},
		ExternalReferences: []*sbom.ExternalReference{
			{
				Url:     "https://example.com/web",
				Type:    sbom.ExternalReference_WEBSITE,
				Comment: "the site",
				Hashes:  map[int32]string{int32(sbom.HashAlgorithm_SHA256): "abcdef0123456789"},
			},
			{Url: "https://example.com/vcs", Type: sbom.ExternalReference_VCS},
		},
		Properties: []*sbom.Property{
			{Name: "a-property", Data: "its value"},
		},
	}

	file := &sbom.Node{
		Id:     "file-1",
		Type:   sbom.Node_FILE,
		Name:   "a/file.txt",
		Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): "abcdef0123456789"},
	}

	original := &sbom.Document{
		Metadata: &sbom.Metadata{
			Id:            "urn:uuid:11111111-2222-3333-4444-555555555555",
			Version:       "7",
			Date:          date,
			DocumentTypes: []*sbom.DocumentType{{Type: &docType}},
		},
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{pkg, file},
			Edges:        []*sbom.Edge{{Type: sbom.Edge_contains, From: pkg.Id, To: []string{file.Id}}},
			RootElements: []string{pkg.Id},
		},
	}

	got := cdxRoundTrip(t, original)

	require.Equal(t, original.Metadata.Id, got.Metadata.Id)
	require.Equal(t, original.Metadata.Version, got.Metadata.Version)
	require.Equal(t, date.AsTime(), got.Metadata.Date.AsTime())
	require.Len(t, got.Metadata.DocumentTypes, 1)
	require.NotNil(t, got.Metadata.DocumentTypes[0].Type)
	require.Equal(t, docType, *got.Metadata.DocumentTypes[0].Type)

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
		{"description", pkg.Description, gotPkg.Description},
		{"copyright", pkg.Copyright, gotPkg.Copyright},
		{"licenses", pkg.Licenses, gotPkg.Licenses},
		{"license concluded", pkg.LicenseConcluded, gotPkg.LicenseConcluded},
		{"purposes", pkg.PrimaryPurpose, gotPkg.PrimaryPurpose},
		{"hashes", pkg.Hashes, gotPkg.Hashes},
		{"identifiers", pkg.Identifiers, gotPkg.Identifiers},
	} {
		require.Equal(t, f.want, f.have, "package %s", f.name)
	}

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
		if len(want.Hashes) > 0 {
			require.Equal(t, want.Hashes, have.Hashes, "reference to %s", want.Url)
		}
	}

	require.Equal(t, pkg.Properties, gotPkg.Properties)

	gotFile := got.NodeList.GetNodeByID(file.Id)
	require.NotNil(t, gotFile)
	require.Equal(t, sbom.Node_FILE, gotFile.Type)
	require.Equal(t, file.Name, gotFile.Name)
	require.Equal(t, file.Hashes, gotFile.Hashes)
}

// TestRoundTripCDXLicenses pins the licensing contract: protobom separates a
// concluded licence from the declared list, CycloneDX holds a single license
// collection, and the reader derives the concluded expression by joining it.
func TestRoundTripCDXLicenses(t *testing.T) {
	for name, tc := range map[string]struct {
		concluded         string
		declared          []string
		expectedConcluded string
		expectedDeclared  []string
	}{
		"single license": {
			"MIT", []string{"MIT"}, "MIT", []string{"MIT"},
		},
		"several declared come back joined as concluded": {
			"", []string{"MIT", "Apache-2.0"}, "MIT OR Apache-2.0", []string{"MIT", "Apache-2.0"},
		},
		"an expression survives as itself": {
			"", []string{"(MIT OR GPL-2.0-only)"}, "(MIT OR GPL-2.0-only)", []string{"(MIT OR GPL-2.0-only)"},
		},
		// TODO(degradation): CycloneDX below 1.6 cannot state a concluded
		// license apart from the declared ones (1.6 added the license
		// acknowledgement field, which the mapping does not use yet), so a
		// concluded license with no declared counterpart is lost.
		"concluded alone is lost": {
			"GPL-3.0-or-later", nil, "", []string{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := cdxRoundTrip(t, cdxOneNodeDoc(&sbom.Node{
				Id: "root", Type: sbom.Node_PACKAGE, Name: "n",
				LicenseConcluded: tc.concluded,
				Licenses:         tc.declared,
			}))
			node := got.NodeList.GetNodeByID("root")
			require.NotNil(t, node)
			require.Equal(t, tc.expectedConcluded, node.LicenseConcluded)
			require.Equal(t, tc.expectedDeclared, node.Licenses)
		})
	}
}

// TestRoundTripCDXEveryVocabulary walks every value of the vocabularies the
// CycloneDX mapping covers, so a value only one side knows is caught here
// rather than in a document that quietly lost or changed a field.
func TestRoundTripCDXEveryVocabulary(t *testing.T) {
	// Purposes CycloneDX has no component type for; each collapses onto the
	// bucket the serializer sends it to and comes back as the bucket.
	collapses := map[sbom.Purpose]sbom.Purpose{
		sbom.Purpose_EXECUTABLE:    sbom.Purpose_APPLICATION,
		sbom.Purpose_INSTALL:       sbom.Purpose_APPLICATION,
		sbom.Purpose_BOM:           sbom.Purpose_DATA,
		sbom.Purpose_CONFIGURATION: sbom.Purpose_DATA,
		sbom.Purpose_DOCUMENTATION: sbom.Purpose_DATA,
		sbom.Purpose_EVIDENCE:      sbom.Purpose_DATA,
		sbom.Purpose_MANIFEST:      sbom.Purpose_DATA,
		sbom.Purpose_REQUIREMENT:   sbom.Purpose_DATA,
		sbom.Purpose_SPECIFICATION: sbom.Purpose_DATA,
		sbom.Purpose_TEST:          sbom.Purpose_DATA,
		sbom.Purpose_OTHER:         sbom.Purpose_DATA,
		sbom.Purpose_MODULE:        sbom.Purpose_LIBRARY,
		sbom.Purpose_MODEL:         sbom.Purpose_MACHINE_LEARNING_MODEL,
	}

	// Purposes that map to the "file" component type: the reader flips the
	// node itself to a FILE node when it sees them.
	fileBucket := map[sbom.Purpose]bool{
		sbom.Purpose_FILE:    true,
		sbom.Purpose_PATCH:   true,
		sbom.Purpose_SOURCE:  true,
		sbom.Purpose_ARCHIVE: true,
	}

	t.Run("purposes", func(t *testing.T) {
		for value, name := range sbom.Purpose_name {
			purpose := sbom.Purpose(value)
			if purpose == sbom.Purpose_UNKNOWN_PURPOSE {
				continue
			}
			t.Run(name, func(t *testing.T) {
				got := cdxRoundTrip(t, cdxOneNodeDoc(&sbom.Node{
					Id: "root", Type: sbom.Node_PACKAGE, Name: "n",
					PrimaryPurpose: []sbom.Purpose{purpose},
				}))
				node := got.NodeList.GetNodeByID("root")
				require.NotNil(t, node)
				require.Len(t, node.PrimaryPurpose, 1)

				want := purpose
				if collapsed, ok := collapses[purpose]; ok {
					want = collapsed
				}
				if fileBucket[purpose] {
					require.Equal(t, sbom.Node_FILE, node.Type,
						"a %s purpose flips the node to a file", name)
					want = sbom.Purpose_FILE
				}
				require.Equal(t, want, node.PrimaryPurpose[0])
			})
		}
	})

	// Hash algorithms CycloneDX has no name for are dropped on write.
	droppedAlgos := map[sbom.HashAlgorithm]bool{
		sbom.HashAlgorithm_UNKNOWN: true,
		sbom.HashAlgorithm_ADLER32: true,
		sbom.HashAlgorithm_MD2:     true,
		sbom.HashAlgorithm_MD4:     true,
		sbom.HashAlgorithm_MD6:     true,
		sbom.HashAlgorithm_SHA224:  true,
	}

	t.Run("hash algorithms", func(t *testing.T) {
		for value, name := range sbom.HashAlgorithm_name {
			algo := sbom.HashAlgorithm(value)
			t.Run(name, func(t *testing.T) {
				got := cdxRoundTrip(t, cdxOneNodeDoc(&sbom.Node{
					Id: "root", Type: sbom.Node_PACKAGE, Name: "n",
					Hashes: map[int32]string{value: "abc123"},
				}))
				node := got.NodeList.GetNodeByID("root")
				require.NotNil(t, node)
				if droppedAlgos[algo] {
					require.Empty(t, node.Hashes,
						"%s has no CycloneDX name, the hash should be dropped", name)
					return
				}
				require.Equal(t, map[int32]string{value: "abc123"}, node.Hashes)
			})
		}
	})

	// Reference types CycloneDX has no name for; the writer sends each of
	// them to "other", so they cannot come back as themselves. The list is
	// here so that a type leaving the unnamed set is a test failure rather
	// than a silent change.
	unnamedRefs := map[sbom.ExternalReference_ExternalReferenceType]bool{
		sbom.ExternalReference_UNKNOWN:                         true,
		sbom.ExternalReference_BINARY:                          true,
		sbom.ExternalReference_BOWER:                           true,
		sbom.ExternalReference_EOL_NOTICE:                      true,
		sbom.ExternalReference_EXPORT_CONTROL_ASSESSMENT:       true,
		sbom.ExternalReference_FUNDING:                         true,
		sbom.ExternalReference_MAVEN_CENTRAL:                   true,
		sbom.ExternalReference_METRICS:                         true,
		sbom.ExternalReference_NPM:                             true,
		sbom.ExternalReference_NUGET:                           true,
		sbom.ExternalReference_PRIVACY_ASSESSMENT:              true,
		sbom.ExternalReference_PRODUCT_METADATA:                true,
		sbom.ExternalReference_PURCHASE_ORDER:                  true,
		sbom.ExternalReference_QUALITY_ASSESSMENT_REPORT:       true,
		sbom.ExternalReference_RELEASE_HISTORY:                 true,
		sbom.ExternalReference_SECURE_SOFTWARE_ATTESTATION:     true,
		sbom.ExternalReference_SECURITY_FIX:                    true,
		sbom.ExternalReference_SECURITY_OTHER:                  true,
		sbom.ExternalReference_SECURITY_POLICY:                 true,
		sbom.ExternalReference_SECURITY_SWID:                   true,
		sbom.ExternalReference_SOURCE_ARTIFACT:                 true,
		sbom.ExternalReference_VULNERABILITY_DISCLOSURE_REPORT: true,
	}

	t.Run("external reference types", func(t *testing.T) {
		for value, name := range sbom.ExternalReference_ExternalReferenceType_name {
			refType := sbom.ExternalReference_ExternalReferenceType(value)
			t.Run(name, func(t *testing.T) {
				got := cdxRoundTrip(t, cdxOneNodeDoc(&sbom.Node{
					Id: "root", Type: sbom.Node_PACKAGE, Name: "n",
					ExternalReferences: []*sbom.ExternalReference{
						{Url: "https://example.com/x", Type: refType},
					},
				}))
				node := got.NodeList.GetNodeByID("root")
				require.NotNil(t, node)
				require.Len(t, node.ExternalReferences, 1)
				want := refType
				if unnamedRefs[refType] {
					want = sbom.ExternalReference_OTHER
				}
				require.Equal(t, want, node.ExternalReferences[0].Type)
			})
		}
	})

	// Identifier types with no CycloneDX component field are dropped on
	// write.
	// TODO(degradation): a gitoid could be written to the omniborId field
	// CycloneDX added in 1.6.
	droppedIdentifiers := map[sbom.SoftwareIdentifierType]bool{
		sbom.SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE: true,
		sbom.SoftwareIdentifierType_GITOID:                  true,
	}

	t.Run("identifier types", func(t *testing.T) {
		for value, name := range sbom.SoftwareIdentifierType_name {
			idType := sbom.SoftwareIdentifierType(value)
			t.Run(name, func(t *testing.T) {
				identifier := "pkg:generic/x@1.0.0"
				switch idType {
				case sbom.SoftwareIdentifierType_CPE22:
					identifier = "cpe:/a:example:x:1.0.0"
				case sbom.SoftwareIdentifierType_CPE23:
					identifier = "cpe:2.3:a:example:x:1.0.0:*:*:*:*:*:*:*"
				}
				got := cdxRoundTrip(t, cdxOneNodeDoc(&sbom.Node{
					Id: "root", Type: sbom.Node_PACKAGE, Name: "n",
					Identifiers: map[int32]string{value: identifier},
				}))
				node := got.NodeList.GetNodeByID("root")
				require.NotNil(t, node)
				if droppedIdentifiers[idType] {
					require.Empty(t, node.Identifiers,
						"%s has no CycloneDX field, the identifier should be dropped", name)
					return
				}
				require.Equal(t, map[int32]string{value: identifier}, node.Identifiers)
			})
		}
	})

	// TODO(degradation): CycloneDX has a single CPE field, so when a node
	// has both editions only CPE 2.3 survives.
	t.Run("both CPE editions collapse to 2.3", func(t *testing.T) {
		got := cdxRoundTrip(t, cdxOneNodeDoc(&sbom.Node{
			Id: "root", Type: sbom.Node_PACKAGE, Name: "n",
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_CPE22): "cpe:/a:example:x:1.0.0",
				int32(sbom.SoftwareIdentifierType_CPE23): "cpe:2.3:a:example:x:1.0.0:*:*:*:*:*:*:*",
			},
		}))
		node := got.NodeList.GetNodeByID("root")
		require.NotNil(t, node)
		require.Equal(t, map[int32]string{
			int32(sbom.SoftwareIdentifierType_CPE23): "cpe:2.3:a:example:x:1.0.0:*:*:*:*:*:*:*",
		}, node.Identifiers)
	})
}

// edgeSet flattens a nodelist's edges into a comparable map of sorted
// destinations keyed by source and type.
func edgeSet(nl *sbom.NodeList) map[string][]string {
	set := map[string][]string{}
	for _, e := range nl.Edges {
		key := fmt.Sprintf("%s|%s", e.From, e.Type)
		set[key] = append(set[key], e.To...)
	}
	for _, tos := range set {
		sort.Strings(tos)
	}
	return set
}

// TestRoundTripCDXEveryEdgeType walks every protobom relationship type
// through CycloneDX and back.
//
// CycloneDX states three relationships: containment through component
// nesting, dependency through the dependency graph, and the scope trio
// through the scope attribute. Everything else the serializer writes as a
// dependency entry, so it comes back as dependsOn.
func TestRoundTripCDXEveryEdgeType(t *testing.T) {
	// The scope-carrying types survive as themselves, but CycloneDX states
	// scope as an attribute of the component, not of the relationship: the
	// edge comes back pointing at the component's parent in the tree
	// instead of its original target.
	scoped := map[sbom.Edge_Type]bool{
		sbom.Edge_runtimeDependency: true,
		sbom.Edge_devDependency:     true,
		sbom.Edge_optionalComponent: true,
	}

	for value, name := range sbom.Edge_Type_name {
		edgeType := sbom.Edge_Type(value)
		if edgeType == sbom.Edge_UNKNOWN {
			continue
		}

		t.Run(name, func(t *testing.T) {
			doc := &sbom.Document{
				Metadata: &sbom.Metadata{Id: "urn:uuid:11111111-2222-3333-4444-555555555555"},
				NodeList: &sbom.NodeList{
					Nodes: []*sbom.Node{
						{Id: "root", Type: sbom.Node_PACKAGE, Name: "root"},
						{Id: "a", Type: sbom.Node_PACKAGE, Name: "a"},
						{Id: "b", Type: sbom.Node_PACKAGE, Name: "b"},
					},
					RootElements: []string{"root"},
				},
			}

			expected := map[string][]string{}
			if edgeType == sbom.Edge_contains {
				// Containment is a chain so each contains edge has a
				// single parent to be expressed under.
				doc.NodeList.Edges = []*sbom.Edge{
					{Type: sbom.Edge_contains, From: "root", To: []string{"a"}},
					{Type: sbom.Edge_contains, From: "a", To: []string{"b"}},
				}
				expected["root|contains"] = []string{"a"}
				expected["a|contains"] = []string{"b"}
			} else {
				doc.NodeList.Edges = []*sbom.Edge{
					{Type: sbom.Edge_contains, From: "root", To: []string{"a", "b"}},
					{Type: edgeType, From: "a", To: []string{"b"}},
				}
				expected["root|contains"] = []string{"a", "b"}
				switch {
				case scoped[edgeType]:
					expected[fmt.Sprintf("a|%s", edgeType)] = []string{"root"}
				default:
					expected["a|dependsOn"] = []string{"b"}
				}
			}

			got := cdxRoundTrip(t, doc)
			require.Equal(t, expected, edgeSet(got.NodeList), "%s did not keep its contract", name)
		})
	}
}
