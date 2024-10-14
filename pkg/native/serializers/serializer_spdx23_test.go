package serializers

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/require"
)

func TestExtRefCategoryFromProtobomExtRef(t *testing.T) {
	s23 := NewSPDX23()
	for extRefType, name := range sbom.ExternalReference_ExternalReferenceType_name {
		t.Run(name, func(t *testing.T) {
			res := s23.extRefCategoryFromProtobomExtRef(&sbom.ExternalReference{
				Type: sbom.ExternalReference_ExternalReferenceType(extRefType),
			})

			switch sbom.ExternalReference_ExternalReferenceType(extRefType) {
			case sbom.ExternalReference_BOWER, sbom.ExternalReference_MAVEN_CENTRAL,
				sbom.ExternalReference_NPM, sbom.ExternalReference_NUGET:
				require.Equal(t, spdx.CategoryPackageManager, res)
			case sbom.ExternalReference_SECURITY_ADVISORY, sbom.ExternalReference_SECURITY_FIX,
				sbom.ExternalReference_SECURITY_OTHER:
				require.Equal(t, spdx.CategorySecurity, res)
			default:
				require.Equal(t, spdxOther, res)
			}
		})
	}
}

func TestExtRefTypeFromProtobomExtRef(t *testing.T) {
	s23 := NewSPDX23()
	for extRefType, name := range sbom.ExternalReference_ExternalReferenceType_name {
		t.Run(name, func(t *testing.T) {
			extRefType := extRefType
			res := s23.extRefTypeFromProtobomExtRef(&sbom.ExternalReference{
				Type: sbom.ExternalReference_ExternalReferenceType(extRefType),
			})

			switch sbom.ExternalReference_ExternalReferenceType(extRefType) {
			case sbom.ExternalReference_BOWER:
				require.Equal(t, spdx.PackageManagerBower, res)
			case sbom.ExternalReference_MAVEN_CENTRAL:
				require.Equal(t, spdx.PackageManagerMavenCentral, res)
			case sbom.ExternalReference_NPM:
				require.Equal(t, spdx.PackageManagerNpm, res)
			case sbom.ExternalReference_NUGET:
				require.Equal(t, spdx.PackageManagerNuGet, res)
			case sbom.ExternalReference_OTHER:
				require.Equal(t, spdxOther, res)
			case sbom.ExternalReference_SECURITY_ADVISORY:
				require.Equal(t, spdx.SecurityAdvisory, res)
			case sbom.ExternalReference_SECURITY_FIX:
				require.Equal(t, spdx.SecurityFix, res)
			case sbom.ExternalReference_SECURITY_OTHER:
				require.Equal(t, spdx.SecurityUrl, res)
			default:
				require.Equal(t, spdxOther, res)
			}
		})
	}
}

func TestSpdxNamespaceFromProtobomID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sut      string
		expected string
		options  SPDX23Options
		mustErr  bool
	}{
		{
			name:     "plain-uri-no-fragment",
			sut:      "https://spdx.org/spdxdocs/28b3c8c8-687c-4df5-9744-ee8e7d644392",
			expected: "https://spdx.org/spdxdocs/28b3c8c8-687c-4df5-9744-ee8e7d644392",
			options:  DefaultSPDX23Options,
			mustErr:  false,
		},
		{
			name:     "plain-uri-valid-fragment",
			sut:      "https://spdx.org/spdxdocs/48ddaa40-309a-40f7-8a8a-643a2262b144#SPDXRef-DOCUMENT",
			expected: "https://spdx.org/spdxdocs/48ddaa40-309a-40f7-8a8a-643a2262b144",
			options:  DefaultSPDX23Options,
			mustErr:  false,
		},
		{
			name:    "plain-uri-valid-fragment-fail",
			sut:     "https://spdx.org/spdxdocs/48ddaa40-309a-40f7-8a8a-643a2262b144#OtherRef",
			options: SPDX23Options{FailOnInvalidDocIdFragment: true},
			mustErr: true,
		},
		{
			name:     "plain-uri-valid-fragment-nofail",
			sut:      "https://spdx.org/spdxdocs/48ddaa40-309a-40f7-8a8a-643a2262b144#OtherRef",
			expected: "https://spdx.org/spdxdocs/48ddaa40-309a-40f7-8a8a-643a2262b144",
			options:  SPDX23Options{FailOnInvalidDocIdFragment: false},
			mustErr:  false,
		},
		{
			name:     "urn",
			sut:      "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
			expected: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
			options:  DefaultSPDX23Options,
			mustErr:  false,
		},
		{
			name:     "random-string",
			sut:      "yolo",
			expected: "yolo",
			options:  DefaultSPDX23Options,
			mustErr:  false,
		},
		{
			name:     "package-url",
			sut:      "pkg:npm/%40angular/animation@12.3.1",
			expected: "pkg:npm/%40angular/animation@12.3.1",
			options:  DefaultSPDX23Options,
			mustErr:  false,
		},
		{
			name:    "blank-url-fail",
			sut:     "",
			options: SPDX23Options{GenerateDocumentID: false},
			mustErr: true,
		},
		{
			name:     "blank-url",
			sut:      "",
			expected: "*",
			options:  DefaultSPDX23Options,
			mustErr:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := spdxNamespaceFromProtobomID(tc.options, tc.sut)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.expected == "*" {
				require.NotEmpty(t, r)
			} else {
				require.Equal(t, tc.expected, r)
			}
		})
	}
}
