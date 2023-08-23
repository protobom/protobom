package writer

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	protospdx "github.com/bom-squad/protobom/pkg/formats/spdx"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer/options"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"sigs.k8s.io/release-utils/version"
)

type SerializerSPDX23 struct{}

func (s *SerializerSPDX23) Render(opts options.Options, doc interface{}, wr io.Writer) error {
	encoder := json.NewEncoder(wr)
	encoder.SetIndent("", strings.Repeat(" ", opts.Indent))
	if err := encoder.Encode(doc.(*spdx.Document)); err != nil {
		return fmt.Errorf("encoding sbom to stream: %w", err)
	}

	return nil
}

// Serialize takes a protobom and returns an SPDX 2.3 struct
func (s *SerializerSPDX23) Serialize(opts options.Options, bom *sbom.Document) (interface{}, error) {
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

	packages, err := buildPackages(bom)
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
			if algoVal, ok := sbom.HashAlgorithm_value[algo]; ok {
				spdxAlgo := sbom.HashAlgorithm(algoVal).ToSPDX()
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

func buildPackages(bom *sbom.Document) ([]*spdx.Package, error) { //nolint:unparam
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
			PrimaryPackagePurpose:     node.PrimaryPurpose,
			Annotations:               []v2_3.Annotation{},

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
			if algoVal, ok := sbom.HashAlgorithm_value[algo]; ok {
				spdxAlgo := sbom.HashAlgorithm(algoVal).ToSPDX()
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
			if e.ToSPDX2Type() == "" || e.Url == "" {
				// TODO(degradation): Handle incomplete external references
				continue
			}
			p.PackageExternalReferences = append(p.PackageExternalReferences, &v2_3.PackageExternalReference{
				Category:           e.ToSPDX2Category(),
				RefType:            e.ToSPDX2Type(),
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
