package unserializers

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/require"
)

func TestSPDXExtRefToProtobomEnum(t *testing.T) {
	s23 := NewSPDX23()
	for _, tc := range []struct {
		sut          spdx.PackageExternalReference
		isIdentifier bool
		expected     sbom.ExternalReference_ExternalReferenceType
		shouldErr    bool
	}{
		// Category: package manager
		{
			spdx.PackageExternalReference{Category: spdx.CategoryPackageManager, RefType: spdx.PackageManagerBower},
			false, sbom.ExternalReference_BOWER, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategoryPackageManager, RefType: spdx.PackageManagerMavenCentral},
			false, sbom.ExternalReference_MAVEN_CENTRAL, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategoryPackageManager, RefType: spdx.PackageManagerNpm},
			false, sbom.ExternalReference_NPM, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategoryPackageManager, RefType: spdx.PackageManagerNuGet},
			false, sbom.ExternalReference_NUGET, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategoryPackageManager, RefType: spdx.PackageManagerPURL},
			true, -1, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategoryPackageManager, RefType: "chacha"},
			false, 0, true,
		},
		// Category: Security
		{
			spdx.PackageExternalReference{Category: spdx.CategorySecurity, RefType: spdx.SecurityAdvisory},
			false, sbom.ExternalReference_SECURITY_ADVISORY, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategorySecurity, RefType: spdx.SecurityFix},
			false, sbom.ExternalReference_SECURITY_FIX, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategorySecurity, RefType: spdx.SecuritySwid},
			false, sbom.ExternalReference_SECURITY_SWID, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategorySecurity, RefType: spdx.SecurityUrl},
			false, sbom.ExternalReference_SECURITY_OTHER, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategorySecurity, RefType: spdx.SecurityCPE22Type},
			true, -1, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategorySecurity, RefType: spdx.SecurityCPE23Type},
			true, -1, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategorySecurity, RefType: "chacha"},
			false, 0, true,
		},
		// Category persistent id
		{
			spdx.PackageExternalReference{Category: spdx.CategoryPersistentId, RefType: spdx.TypePersistentIdGitoid},
			true, -1, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategoryPersistentId, RefType: spdx.TypePersistentIdSwh},
			true, -1, false,
		},
		{
			spdx.PackageExternalReference{Category: spdx.CategoryPersistentId, RefType: "chacha"},
			false, 0, true,
		},
		// TODO(complete this)
	} {
		tc := tc
		t.Run(fmt.Sprintf("%s/%s", tc.sut.Category, tc.sut.RefType), func(t *testing.T) {
			res, isIdentifier, err := s23.extRefToProtobomEnum(&tc.sut)
			if tc.shouldErr {
				require.Error(t, err)
				return
			}
			require.Equal(t, tc.isIdentifier, isIdentifier)
			require.Equal(t, tc.expected, res)
		})
	}
}

func TestExtRefTypeToIdentifierType(t *testing.T) {
	s23 := NewSPDX23()
	for _, tc := range []struct {
		sut      string
		expected sbom.SoftwareIdentifierType
	}{
		{spdx.PackageManagerPURL, sbom.SoftwareIdentifierType_PURL},
		{spdx.SecurityCPE23Type, sbom.SoftwareIdentifierType_CPE23},
		{spdx.SecurityCPE22Type, sbom.SoftwareIdentifierType_CPE22},
		{spdx.TypePersistentIdGitoid, sbom.SoftwareIdentifierType_GITOID},
		{"", sbom.SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE},
	} {
		identifier := s23.extRefTypeToIdentifierType(tc.sut)
		require.Equal(t, tc.expected, identifier)
	}
}

func TestBuildDocumentIdentifier(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		sut   *spdx23.Document
		match func(string) bool
	}{
		{
			name: "normal",
			sut: &spdx23.Document{
				SPDXIdentifier:    "DOCUMENT",
				DocumentNamespace: "https://example.com/document",
			},
			match: func(s string) bool { return s == "https://example.com/document#DOCUMENT" },
		},
		{
			name: "no-namespace",
			sut: &spdx23.Document{
				SPDXIdentifier:    "DOCUMENT",
				DocumentNamespace: "",
			},
			match: func(s string) bool {
				r := regexp.MustCompile(`^https://spdx.org/spdxdocs/protobom-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}#DOCUMENT$`)
				return r.MatchString(s)
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			identifier := buildDocumentIdentifier(tc.sut)
			require.True(t, tc.match(identifier), identifier)
		})
	}
}

func TestAnnotationsMod(t *testing.T) {
	opts := &native.UnserializeOptions{
		Mods: map[mod.Mod]struct{}{},
	}
	opts.Mods[mod.SPDX_READ_ANNOTATIONS_TO_PROPERTIES] = struct{}{}

	for _, tc := range []struct {
		name        string
		opts        *native.UnserializeOptions
		spdxPackage *spdx23.Package
		expected    []*sbom.Property
	}{
		{
			name:        "no-annotations",
			opts:        opts,
			spdxPackage: &spdx23.Package{},
			expected:    []*sbom.Property{},
		},
		{
			name: "one-annotation",
			opts: opts,
			spdxPackage: &spdx23.Package{
				Annotations: []spdx23.Annotation{
					{
						Annotator: common.Annotator{
							Annotator:     "protobom - v1.0.0",
							AnnotatorType: "Tool",
						},
						AnnotationDate:    "1970-01-01T00:00:00Z",
						AnnotationType:    "OTHER",
						AnnotationComment: `{"name": "test", "data": "test data"}`,
					},
				},
			},
			expected: []*sbom.Property{
				{
					Name: "test",
					Data: "test data",
				},
			},
		},
		{
			name: "two-annotation",
			opts: opts,
			spdxPackage: &spdx23.Package{
				Annotations: []spdx23.Annotation{
					{
						Annotator: common.Annotator{
							Annotator:     "protobom - v1.0.0",
							AnnotatorType: "Tool",
						},
						AnnotationDate:    "1970-01-01T00:00:00Z",
						AnnotationType:    "OTHER",
						AnnotationComment: `{"name": "test", "data": "test data"}`,
					},
					{
						Annotator: common.Annotator{
							Annotator:     "protobom - v1.0.0",
							AnnotatorType: "Tool",
						},
						AnnotationDate:    "1970-01-01T00:00:00Z",
						AnnotationType:    "OTHER",
						AnnotationComment: `{"name": "second", "data": "test data 2"}`,
					},
				},
			},
			expected: []*sbom.Property{
				{Name: "test", Data: "test data"},
				{Name: "second", Data: "test data 2"},
			},
		},
		{
			name: "invalid-annotation",
			opts: opts,
			spdxPackage: &spdx23.Package{
				Annotations: []spdx23.Annotation{
					{
						Annotator: common.Annotator{
							Annotator:     "protobom - v1.0.0",
							AnnotatorType: "Tool",
						},
						AnnotationDate:    "1970-01-01T00:00:00Z",
						AnnotationType:    "OTHER",
						AnnotationComment: `something else {`,
					},
				},
			},
			expected: []*sbom.Property{},
		},
		{
			name: "other-annotation",
			opts: opts,
			spdxPackage: &spdx23.Package{
				Annotations: []spdx23.Annotation{
					{
						Annotator: common.Annotator{
							Annotator:     "John Doe Sr",
							AnnotatorType: "Person",
						},
						AnnotationDate:    "1970-01-01T00:00:00Z",
						AnnotationType:    "OTHER",
						AnnotationComment: `{"name": "second", "data": "test data 2"}`,
					},
				},
			},
			expected: []*sbom.Property{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := NewSPDX23().packageToNode(tc.opts, tc.spdxPackage)
			require.Len(t, node.Properties, len(tc.expected))
			for i := range node.Properties {
				require.Equal(t, tc.expected[i].Name, node.Properties[i].Name)
				require.Equal(t, tc.expected[i].Data, node.Properties[i].Data)
			}
		})
	}
}
