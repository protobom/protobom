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
