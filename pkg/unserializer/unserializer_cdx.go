package unserializer

import (
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bom-squad/protobom/pkg/sbom"
)

var _ CDXUnserializer = &UnserializerCDX{}

type UnserializerCDX struct{}

func (u *UnserializerCDX) Metadata(bom *cdx.BOM) (*sbom.Metadata, *sbom.NodeList, error) {
	md := &sbom.Metadata{
		Id:      bom.SerialNumber,
		Version: fmt.Sprintf("%d", bom.Version),
		// Name:    ,
		Date:          &timestamppb.Timestamp{},
		Tools:         []*sbom.Tool{},
		Authors:       []*sbom.Person{},
		DocumentTypes: []*sbom.DocumentType{},

		// Comment: metadata.Comment,
	}

	metadata := bom.Metadata
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

	var nodeList *sbom.NodeList
	if metadata.Component != nil {
		nl, err := u.NodeList(metadata.Component)
		if err != nil {
			return nil, nil, fmt.Errorf("converting main bom component to node: %w", err)
		}
		if len(nl.RootElements) > 1 {
			logrus.Warnf("root nodelist has %d components, this should not happen", len(nl.RootElements))
		}
		nodeList = nl
	}

	return md, nodeList, nil
}

// componentToNodes takes a CycloneDX component and computes its graph fragment,
// returning a nodelist
func (u *UnserializerCDX) NodeList(component *cdx.Component) (*sbom.NodeList, error) {
	node, err := u.Node(component)
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
			subList, err := u.NodeList(&(*component.Components)[i])
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

func (u *UnserializerCDX) Node(c *cdx.Component) (*sbom.Node, error) {
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
		Hashes:             map[string]string{},
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

			if _, ok := node.Hashes[algo.String()]; ok {
				// TODO(degradation): Data loss from two hashes of the same algorithm
				continue
			}
			node.Hashes[algo.String()] = h.Value
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
func (u *UnserializerCDX) licenseChoicesToLicenseList(lcs *cdx.Licenses) []string {
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
func (u *UnserializerCDX) licenseChoicesToLicenseString(lcs *cdx.Licenses) string {
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
func (u *UnserializerCDX) phaseToSBOMType(ph *cdx.LifecyclePhase) *sbom.DocumentType_SBOMType {
	phase := *ph
	switch phase {
	case cdx.LifecyclePhaseBuild:
		return sbom.DocumentType_BUILD.Enum()
	case cdx.LifecyclePhaseDecommission:
		return sbom.DocumentType_OTHER.Enum()
	case cdx.LifecyclePhaseDesign:
		return sbom.DocumentType_DESIGN.Enum()
	case cdx.LifecyclePhaseDiscovery:
		return sbom.DocumentType_OTHER.Enum()
	case cdx.LifecyclePhaseOperations:
		return sbom.DocumentType_OTHER.Enum()
	case cdx.LifecyclePhasePostBuild:
		return sbom.DocumentType_OTHER.Enum()
	case cdx.LifecyclePhasePreBuild:
		return sbom.DocumentType_OTHER.Enum()
	default:
		return nil
	}
}
