package serializers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	protospdx "github.com/protobom/protobom/pkg/formats/spdx"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"sigs.k8s.io/release-utils/version"
)

var _ native.Serializer = &SPDX23{}

type SPDX23 struct{}

type SPDX3Options struct {
	Indent int
}

const spdxOther = "OTHER"

func NewSPDX23() *SPDX23 {
	return &SPDX23{}
}

func (s *SPDX23) Render(doc interface{}, wr io.Writer, o *native.RenderOptions, _ interface{}) error {
	// TODO: add support for XML
	encoder := json.NewEncoder(wr)
	encoder.SetIndent("", strings.Repeat(" ", o.Indent))
	if err := encoder.Encode(doc.(*spdx.Document)); err != nil {
		return fmt.Errorf("encoding sbom to stream: %w", err)
	}

	return nil
}

// Serialize takes a protobom and returns an SPDX 2.3 struct
func (s *SPDX23) Serialize(bom *sbom.Document, _ *native.SerializeOptions, _ interface{}) (interface{}, error) {
	if bom == nil {
		return nil, errors.New("document is nil, unable to serialize to SPDX 2.3")
	}
	if bom.Metadata == nil {
		return nil, errors.New("document metadata is nil, unable to serialize to SPDX 2.3")
	}
	doc := &spdx.Document{
		SPDXVersion:       spdx.Version,
		DataLicense:       spdx.DataLicense,
		SPDXIdentifier:    protospdx.DOCUMENT,
		DocumentName:      bom.Metadata.Name,
		DocumentNamespace: "https://spdx.org/spdxdocs/", // TODO(puerco): Think how to handle namespacing
		DocumentComment:   bom.Metadata.Comment,

		CreationInfo: &spdx.CreationInfo{
			LicenseListVersion: "3.20", // https://spdx.org/licenses/
			Creators: []spdx.Creator{
				// Register protobom as one of the document creation tools
				{
					Creator:     fmt.Sprintf("protobom-%s", version.GetVersionInfo().GitVersion),
					CreatorType: "Tool",
				},
			},

			// Interesting, should we keep the original date?
			Created: time.Now().UTC().Format(time.RFC3339),
			// CreatorComment: bom.Metadata.Authors(),
			// CreatorComment: bom.Metadata.... /// TODO(puerco): Missing in the proto
		},
	}

	for _, t := range bom.Metadata.Tools {
		// TODO(degradation): SPDX is prescriptive on how this field is structured
		// it is a tool identifier word separated from the version with a dash.
		// We should transform the field value
		// Ref: https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field
		name := t.Name
		if t.Version != "" {
			name = fmt.Sprintf("%s-%s", t.Name, t.Version)
		}

		// TODO(degradation): Tool vendor gets lost here

		doc.CreationInfo.Creators = append(doc.CreationInfo.Creators, spdx.Creator{
			Creator:     name,
			CreatorType: protospdx.Tool,
		})
	}

	packages, err := s.buildPackages(bom)
	if err != nil {
		return nil, fmt.Errorf("building SPDX packages: %s", err)
	}

	files, err := buildFiles(bom)
	if err != nil {
		return nil, fmt.Errorf("building SPDX file list: %s", err)
	}

	rels, err := buildRelationships(bom)
	if err != nil {
		return nil, fmt.Errorf("building relationships: %w", err)
	}

	for _, id := range bom.NodeList.RootElements {
		rels = append(rels, &spdx.Relationship{
			RefA:                common.MakeDocElementID("", protospdx.DOCUMENT),
			RefB:                common.MakeDocElementID("", id),
			Relationship:        common.TypeRelationshipDescribe,
			RelationshipComment: "",
		})
	}

	// TODO(puerco): Files in packages
	// TODO(puerco): Package verification data

	doc.Packages = packages
	doc.Files = files
	doc.Relationships = rels

	return doc, nil
}

func buildRelationships(bom *sbom.Document) ([]*spdx.Relationship, error) { //nolint:unparam
	relationships := []*spdx.Relationship{}
	for _, e := range bom.NodeList.Edges {
		for _, dest := range e.To {
			rel := spdx.Relationship{
				RefA:         common.MakeDocElementID("", e.From),
				RefB:         common.MakeDocElementID("", dest),
				Relationship: e.Type.ToSPDX2(),
				// RelationshipComment: "",
			}
			relationships = append(relationships, &rel)
		}
	}
	return relationships, nil
}

func buildFiles(bom *sbom.Document) ([]*spdx.File, error) { //nolint:unparam
	files := []*spdx.File{}
	for _, node := range bom.NodeList.Nodes {
		if node.Type == sbom.Node_PACKAGE {
			continue
		}

		f := spdx.File{
			FileName:           node.Name,
			FileSPDXIdentifier: common.ElementID(node.Id),
			FileTypes:          node.FileTypes,
			Checksums:          []common.Checksum{},
			LicenseConcluded:   node.LicenseConcluded,
			// LicenseInfoInFiles:   []string{}, << bug in SPDX
			LicenseComments:   node.LicenseComments,
			FileCopyrightText: strings.TrimSpace(node.Copyright),
			FileComment:       node.Comment,
			// FileNotice:           node.File, // Missing?
			FileAttributionTexts: node.Attribution,
			Annotations:          []v2_3.Annotation{},
		}

		if f.FileCopyrightText == "" {
			f.FileCopyrightText = protospdx.NONE
		}

		for algo, hash := range node.Hashes {
			if _, ok := sbom.HashAlgorithm_name[algo]; ok {
				spdxAlgo := sbom.HashAlgorithm(algo).ToSPDX()
				if spdxAlgo == "" {
					// TODO(degradation): Data loss. How do we handle more algos?
					continue
				}
				f.Checksums = append(f.Checksums, common.Checksum{
					Algorithm: spdxAlgo,
					Value:     hash,
				})
			}
		}
		files = append(files, &f)
	}
	return files, nil
}

func (s *SPDX23) buildPackages(bom *sbom.Document) ([]*spdx.Package, error) { //nolint:unparam
	packages := []*spdx.Package{}
	for _, node := range bom.NodeList.Nodes {
		if node.Type == sbom.Node_FILE {
			continue
		}

		p := spdx.Package{
			IsUnpackaged:          false,
			PackageName:           node.Name,
			PackageSPDXIdentifier: common.ElementID(node.Id),
			PackageVersion:        node.Version,
			PackageFileName:       node.FileName,
			// PackageSupplier:             &common.Supplier{},
			// PackageOriginator:           &common.Originator{},
			PackageDownloadLocation: node.UrlDownload,
			// FilesAnalyzed:               false,
			// IsFilesAnalyzedTagPresent:   false,
			// PackageVerificationCode:     &common.PackageVerificationCode{},
			PackageChecksums:            []common.Checksum{},
			PackageHomePage:             node.UrlHome,
			PackageSourceInfo:           node.SourceInfo,
			PackageLicenseConcluded:     node.LicenseConcluded,
			PackageLicenseInfoFromFiles: []string{},
			// PackageLicenseDeclared:      node.Licenses[0],
			PackageLicenseComments:    node.LicenseComments,
			PackageCopyrightText:      strings.TrimSpace(node.Copyright),
			PackageSummary:            node.Summary,
			PackageDescription:        node.Description,
			PackageComment:            node.Comment,
			PackageExternalReferences: []*v2_3.PackageExternalReference{},
			PackageAttributionTexts:   node.Attribution,
			// PrimaryPackagePurpose:     node.PrimaryPurpose,
			Annotations: []v2_3.Annotation{},

			// The files field may never be used... Or should it?
			// We are mirroring the protbom graph in the SPDX relationship
			// structure so they don't need to be added here and
			// the resulting document is still valid.
			//
			// There may be tools that rely on files added in the list so
			// at some point we may need to think of supporting this as an
			// option.
			// Files:                       []*v2_3.File{},
		}

		if len(node.PrimaryPurpose) > 0 && (node.PrimaryPurpose[0] != sbom.Purpose_UNKNOWN_PURPOSE) {
			// Allowed values: APPLICATION, FRAMEWORK, LIBRARY, CONTAINER, OPERATING-SYSTEM, DEVICE, FIRMWARE, SOURCE, ARCHIVE, FILE, INSTALL, OTHER

			if len(node.PrimaryPurpose) > 1 {
				// TODO(degradation): Multiple PrimaryPurpose in protobom.Node, but spdx.Package only allows single PrimaryPackagePurpose so we are using the first
				if true { // temp workaround in favor of adding a lint tag
					break
				}
			}

			switch node.PrimaryPurpose[0] {
			case sbom.Purpose_APPLICATION, sbom.Purpose_EXECUTABLE:
				p.PrimaryPackagePurpose = "APPLICATION"
			case sbom.Purpose_FRAMEWORK:
				p.PrimaryPackagePurpose = "FRAMEWORK"
			case sbom.Purpose_LIBRARY, sbom.Purpose_MODULE:
				p.PrimaryPackagePurpose = "LIBRARY"
			case sbom.Purpose_CONTAINER:
				p.PrimaryPackagePurpose = "CONTAINER"
			case sbom.Purpose_OPERATING_SYSTEM:
				p.PrimaryPackagePurpose = "OPERATING-SYSTEM"
			case sbom.Purpose_DEVICE, sbom.Purpose_DEVICE_DRIVER:
				p.PrimaryPackagePurpose = "DEVICE"
			case sbom.Purpose_FIRMWARE:
				p.PrimaryPackagePurpose = "FIRMWARE"
			case sbom.Purpose_SOURCE, sbom.Purpose_PATCH:
				p.PrimaryPackagePurpose = "SOURCE"
			case sbom.Purpose_ARCHIVE:
				p.PrimaryPackagePurpose = "ARCHIVE"
			case sbom.Purpose_FILE:
				p.PrimaryPackagePurpose = "FILE"
			case sbom.Purpose_INSTALL:
				p.PrimaryPackagePurpose = "INSTALL"
			case sbom.Purpose_OTHER, sbom.Purpose_DATA, sbom.Purpose_BOM, sbom.Purpose_CONFIGURATION, sbom.Purpose_DOCUMENTATION, sbom.Purpose_EVIDENCE, sbom.Purpose_MANIFEST, sbom.Purpose_REQUIREMENT, sbom.Purpose_SPECIFICATION, sbom.Purpose_TEST:
				p.PrimaryPackagePurpose = "OTHER"
			case sbom.Purpose_MACHINE_LEARNING_MODEL, sbom.Purpose_MODEL:
				p.PrimaryPackagePurpose = "OTHER"
			case sbom.Purpose_PLATFORM:
				p.PrimaryPackagePurpose = "OTHER"
			default:
				// TODO(degradation): Non-matching primary purpose to component type mapping
				if true { // temp workaround in favor of adding a lint tag
					break
				}
			}
		}

		if node.ReleaseDate != nil {
			p.ReleaseDate = node.ReleaseDate.String()
		}

		if node.BuildDate != nil {
			p.BuiltDate = node.BuildDate.String()
		}

		if node.ValidUntilDate != nil {
			p.ValidUntilDate = node.ValidUntilDate.String()
		}

		if p.PackageDownloadLocation == "" {
			p.PackageDownloadLocation = protospdx.NOASSERTION
		}

		for algo, hash := range node.Hashes {
			if _, ok := sbom.HashAlgorithm_name[algo]; ok {
				spdxAlgo := sbom.HashAlgorithm(algo).ToSPDX()
				if spdxAlgo == "" {
					// Data loss here.
					// TODO how do we handle when data loss occurs?
					continue
				}
				p.PackageChecksums = append(p.PackageChecksums, common.Checksum{
					Algorithm: spdxAlgo,
					Value:     hash,
				})
			}
		}

		for _, e := range node.ExternalReferences {
			category := s.extRefCategoryFromProtobomExtRef(e)

			if e.Url == "" {
				// TODO(degradation): Handle incomplete external references
				continue
			}
			p.PackageExternalReferences = append(p.PackageExternalReferences, &v2_3.PackageExternalReference{
				Category:           category,
				RefType:            s.extRefTypeFromProtobomExtRef(e),
				Locator:            e.Url,
				ExternalRefComment: e.Comment,
			})
		}

		for i := range node.Identifiers {
			p.PackageExternalReferences = append(p.PackageExternalReferences, &v2_3.PackageExternalReference{
				Category: sbom.SoftwareIdentifierType(i).ToSPDX2Category(),
				RefType:  sbom.SoftwareIdentifierType(i).ToSPDX2Type(),
				Locator:  node.Identifiers[i],
			})
		}

		if len(node.Suppliers) > 0 {
			// TODO(degradation): URL, Phone are lost if set
			// TODO(degradation): If is more than one supplier, it will be lost
			p.PackageSupplier = &spdx.Supplier{
				Supplier:     node.Suppliers[0].ToSPDX2ClientString(),
				SupplierType: node.Suppliers[0].ToSPDX2ClientOrg(),
			}
		}

		if len(node.Originators) > 0 {
			// TODO(degradation): URL, Phone are lost if set
			// TODO(degradation): If is more than one originator, it will be lost
			p.PackageSupplier = &spdx.Supplier{
				Supplier:     node.Originators[0].ToSPDX2ClientString(),
				SupplierType: node.Originators[0].ToSPDX2ClientOrg(),
			}
		}

		// TODO(puerco): Reconcile file in packages
		packages = append(packages, &p)
	}
	return packages, nil
}

// ExtRefCategoryFromProtobomExtRef reads a protobom external reference struct and returns a
// string with the corresponding category
func (s *SPDX23) extRefCategoryFromProtobomExtRef(extref *sbom.ExternalReference) string {
	switch extref.Type {
	case sbom.ExternalReference_BOWER, sbom.ExternalReference_MAVEN_CENTRAL,
		sbom.ExternalReference_NPM, sbom.ExternalReference_NUGET:
		return spdx.CategoryPackageManager
	case sbom.ExternalReference_SECURITY_ADVISORY, sbom.ExternalReference_SECURITY_FIX:
		return spdx.CategorySecurity
	case sbom.ExternalReference_SECURITY_OTHER:
		// This is mapped...
		return spdx.CategorySecurity

	// ... the other security* are data loss hacks
	// TODO(degradation): all the security type could be dumped
	// as security+url but aplications need to opt in
	//
	// if hack then
	// case sbom.ExternalReference_SECURITY_*:
	// return spdx.CategorySecurity
	default:
		return spdxOther
	}
}

// extRefTypeFromProtobomExtRef returns the spdx external reference type
// from a protobom external reference
func (s *SPDX23) extRefTypeFromProtobomExtRef(extref *sbom.ExternalReference) string {
	switch extref.Type {
	case sbom.ExternalReference_BOWER:
		return spdx.PackageManagerBower
	case sbom.ExternalReference_MAVEN_CENTRAL:
		return spdx.PackageManagerMavenCentral
	case sbom.ExternalReference_NPM:
		return spdx.PackageManagerNpm
	case sbom.ExternalReference_NUGET:
		return spdx.PackageManagerNuGet
	case sbom.ExternalReference_OTHER:
		return spdxOther
	case sbom.ExternalReference_SECURITY_ADVISORY:
		return spdx.SecurityAdvisory
	case sbom.ExternalReference_SECURITY_FIX:
		return spdx.SecurityFix
	case sbom.ExternalReference_SECURITY_OTHER:
		return spdx.SecurityUrl
	default:
		return spdxOther
	}
}
