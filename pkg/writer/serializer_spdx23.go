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
		SPDXIdentifier:    common.ElementID(bom.Metadata.Id),
		DocumentName:      bom.Metadata.Name,
		DocumentNamespace: "https://spdx.org/spdxdocs/", // TODO(puerco): Think how to handle namespacing
		DocumentComment:   bom.Metadata.Comment,

		CreationInfo: &spdx.CreationInfo{
			LicenseListVersion: "3.20", // https://spdx.org/licenses/
			Creators: []spdx.Creator{
				// Add data from the protobom
				{
					Creator:     "protobom/0.0.0",
					CreatorType: "Tool",
				},
			},

			// Interesting, should we keep the original date?
			Created: time.Now().UTC().Format(time.RFC3339),
			// CreatorComment: bom.Metadata.Authors(),
			// CreatorComment: bom.Metadata.... /// TODO(puerco): Missing in the proto
		},
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
			RefA:                common.MakeDocElementID("", bom.Metadata.Id),
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

func buildRelationships(bom *sbom.Document) ([]*spdx.Relationship, error) {
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

func buildFiles(bom *sbom.Document) ([]*spdx.File, error) {
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
			// FileContributors:     []string{},
			FileAttributionTexts: node.Attribution,
			Annotations:          []v2_3.Annotation{},
		}

		if f.FileCopyrightText == "" {
			f.FileCopyrightText = "NONE"
		}

		for algo, hash := range node.Hashes {
			if algoVal, ok := sbom.HashAlgorithm_value[algo]; ok {
				spdxAlgo := sbom.HashAlgorithm(algoVal).ToSPDX()
				if spdxAlgo == "" {
					// Data loss here.
					// TODO how do we handle when data loss occurs?
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

func buildPackages(bom *sbom.Document) ([]*spdx.Package, error) {
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
			// We are mirroring the probom graph in the SPDX relationship
			// structure so they don't need to be added here and
			// the resulting document is valid.
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

		// TODO(puerco): Supplier
		// TODO(puerco): Originator
		packages = append(packages, &p)
	}
	return packages, nil
}
