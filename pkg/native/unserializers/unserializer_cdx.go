package unserializers

import (
	"fmt"
	"io"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	cdxformats "github.com/bom-squad/protobom/pkg/formats/cyclonedx"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bom-squad/protobom/pkg/native"
	"github.com/bom-squad/protobom/pkg/sbom"
)

var _ native.Unserializer = &CDX{}

type CDX struct {
	version  string
	encoding string
}

func NewCDX(version, encoding string) *CDX {
	return &CDX{
		version:  version,
		encoding: encoding,
	}
}

// ParseStream reads a CycloneDX 1.5 from stream r usinbg the offcial CycloneDX
// libraries and returns a protobom document with its data.
func (u *CDX) Unserialize(r io.Reader, _ *native.UnserializeOptions) (*sbom.Document, error) {
	bom := new(cdx.BOM)

	encoding, err := cdxformats.ParseEncoding(u.encoding)
	if err != nil {
		return nil, err
	}
	decoder := cdx.NewBOMDecoder(r, encoding)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decoding cyclonedx: %w", err)
	}

	md := &sbom.Metadata{
		Id:      bom.SerialNumber,
		Version: fmt.Sprintf("%d", bom.Version),
		// Name:    ,
		Date:          &timestamppb.Timestamp{},
		Tools:         []*sbom.Tool{},
		Authors:       []*sbom.Person{},
		DocumentTypes: []*sbom.DocumentType{},
	}

	doc := &sbom.Document{
		Metadata: md,
		NodeList: &sbom.NodeList{},
	}

	metadata := bom.Metadata
	if metadata != nil {
		if metadata.Lifecycles != nil {
			for _, lc := range *metadata.Lifecycles {
				lc := lc
				name := lc.Name
				desc := lc.Description
				t := u.phaseToSBOMType(&lc.Phase)
				if name == "" {
					name = string(lc.Phase)
				}

				md.DocumentTypes = append(md.DocumentTypes, &sbom.DocumentType{
					Name:        &name,
					Description: &desc,
					Type:        t,
				})
			}
		}
		if metadata.Component != nil {
			nl, err := u.componentToNodeList(metadata.Component)
			if err != nil {
				return nil, fmt.Errorf("converting main bom component to node: %w", err)
			}
			if len(nl.RootElements) > 1 {
				logrus.Warnf("root nodelist has %d components, this should not happen", len(nl.RootElements))
			}
			doc.NodeList.Add(nl)
		}
	}

	// Cycle all components and get their graph fragments
	if bom.Components != nil {
		for i := range *bom.Components {
			nl, err := u.componentToNodeList(&(*bom.Components)[i])
			if err != nil {
				return nil, fmt.Errorf("converting component to node: %w", err)
			}

			if len(doc.NodeList.RootElements) == 0 {
				doc.NodeList.Add(nl)
			} else {
				if err := doc.NodeList.RelateNodeListAtID(nl, doc.NodeList.RootElements[0], sbom.Edge_contains); err != nil {
					return nil, fmt.Errorf("relating components to root node: %w", err)
				}
			}
		}
	}

	return doc, nil
}

// componentToNodes takes a CycloneDX component and computes its graph fragment,
// returning a nodelist
func (u *CDX) componentToNodeList(component *cdx.Component) (*sbom.NodeList, error) {
	node, err := u.componentToNode(component)
	if err != nil {
		return nil, fmt.Errorf("converting cdx component to node: %w", err)
	}

	nl := &sbom.NodeList{
		Nodes:        []*sbom.Node{node},
		Edges:        []*sbom.Edge{},
		RootElements: []string{node.Id},
	}

	if component.Components != nil {
		for i := range *component.Components {
			subList, err := u.componentToNodeList(&(*component.Components)[i])
			if err != nil {
				return nil, fmt.Errorf("converting subcomponent to nodelist: %w", err)
			}
			if err := nl.RelateNodeListAtID(subList, node.Id, sbom.Edge_contains); err != nil {
				return nil, fmt.Errorf("relating subcomponents to new node: %w", err)
			}
		}
	}

	return nl, nil
}

func (u *CDX) componentToNode(c *cdx.Component) (*sbom.Node, error) { //nolint:unparam
	node := &sbom.Node{
		Id:      c.BOMRef,
		Type:    sbom.Node_PACKAGE,
		Name:    c.Name,
		Version: c.Version,
		// UrlHome:     "", // Perhaps it would make sense to use the supplier URL here
		UrlDownload:        "",
		Licenses:           u.licenseChoicesToLicenseList(c.Licenses),
		LicenseConcluded:   u.licenseChoicesToLicenseString(c.Licenses),
		Copyright:          c.Copyright,
		Hashes:             map[int32]string{},
		PrimaryPurpose:     string(c.Type),
		Description:        c.Description,
		Attribution:        []string{},
		Suppliers:          []*sbom.Person{}, // TODO
		Originators:        []*sbom.Person{}, // TODO
		ExternalReferences: []*sbom.ExternalReference{},
		Identifiers:        map[int32]string{},
		FileTypes:          []string{},
	}

	// type should be one of
	// application | framework | library | container | operating-system | device | firmware | file
	if c.Type == cdx.ComponentTypeFile {
		node.Type = sbom.Node_FILE
	}

	// External references
	// "vcs" "issue-tracker" "website"  "advisories" "bom" "mailing-list"  "social"  "chat" "documentation"
	// "support" "distribution" "license" "build-meta" "build-system" "release-notes" "other"

	// Named external references:
	if c.CPE != "" {
		t := sbom.SoftwareIdentifierType_CPE22
		if strings.HasPrefix(c.CPE, "cpe:2.3") {
			t = sbom.SoftwareIdentifierType_CPE23
		}
		node.Identifiers[int32(t)] = c.CPE
	}

	if c.PackageURL != "" {
		node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = c.PackageURL
	}

	if c.Hashes != nil {
		for _, h := range *c.Hashes {
			algo := sbom.HashAlgorithmFromCDX(h.Algorithm)
			if algo == sbom.HashAlgorithm_UNKNOWN {
				// TODO(degradation): Well, not deprecation but invalid SBOM
				continue
			}

			if _, ok := node.Hashes[int32(algo)]; ok {
				// TODO(degradation): Data loss from two hashes of the same algorithm
				continue
			}
			node.Hashes[int32(algo)] = h.Value
		}
	}

	// Generate a new ID if none is set
	if node.Id == "" {
		node.Id = sbom.NewNodeIdentifier()
	}

	return node, nil
}

// licenseChoicesToLicenseList returns a flat list of license strings combining
// expressions and IDs in one. This function should be part of a license package.
func (u *CDX) licenseChoicesToLicenseList(lcs *cdx.Licenses) []string {
	list := []string{}
	if lcs == nil {
		return list
	}
	for _, lc := range *lcs {
		// TODO(license): This should handle licenses without an ID and
		// create custom licenses or another solution that captures the
		// full cuistom license text.
		if lc.Expression == "" && lc.License.ID == "" {
			continue
		}

		if lc.Expression != "" {
			list = append(list, lc.Expression)
		} else {
			list = append(list, lc.License.ID)
		}
		return list
	}

	return list
}

// licenseChoicesToLicenseString takes the component license data and computes
// a license expression with its license entries. It will return the license or
// expression verbatim if its just a single entry.
// This function is temporary and probably should be part of a more complete
// license package.
func (u *CDX) licenseChoicesToLicenseString(lcs *cdx.Licenses) string {
	if lcs == nil {
		return ""
	}
	s := ""
	for _, lc := range *lcs {
		// TODO(license): This should handle licenses without an ID and
		// create custom licenses or another solution that captures the
		// full cuistom license text.
		if lc.Expression == "" && lc.License.ID == "" {
			continue
		}
		if s != "" {
			s += fmt.Sprintf("(%s) OR ", s)
		}

		newLicense := ""
		if lc.Expression != "" {
			newLicense = lc.Expression
		} else {
			newLicense = lc.License.ID
		}
		if s == "" {
			s = newLicense
		} else {
			s += fmt.Sprintf(" (%s)", newLicense)
		}
	}
	return s
}

// phaseToSBOMType converts a CycloneDX lifecycle phase to an SBOM document type
// note that most of the CycloneDX phases are not mapped to SBOM document types and they would be used as OTHER
// this is a temporary solution until we have a better mapping
// see: https://www.cisa.gov/sites/default/files/2023-04/sbom-types-document-508c.pdf
func (u *CDX) phaseToSBOMType(ph *cdx.LifecyclePhase) *sbom.DocumentType_SBOMType {
	phase := *ph
	switch phase {
	case cdx.LifecyclePhaseBuild:
		return sbom.DocumentType_BUILD.Enum()
	case cdx.LifecyclePhaseDecommission:
		return sbom.DocumentType_DECOMISSION.Enum()
	case cdx.LifecyclePhaseDesign:
		return sbom.DocumentType_DESIGN.Enum()
	case cdx.LifecyclePhaseDiscovery:
		return sbom.DocumentType_DISCOVERY.Enum()
	case cdx.LifecyclePhaseOperations:
		return sbom.DocumentType_DEPLOYED.Enum()
	case cdx.LifecyclePhasePreBuild:
		return sbom.DocumentType_SOURCE.Enum()
	case cdx.LifecyclePhasePostBuild:
		return sbom.DocumentType_ANALYZED.Enum()
	default:
		return nil
	}
}
