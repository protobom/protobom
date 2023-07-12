package reader

import (
	"fmt"
	"io"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bom-squad/protobom/pkg/reader/options"
	"github.com/bom-squad/protobom/pkg/sbom"
)

type UnserializerCDX14 struct{}

// ParseStream reads a CycloneDX 1.4 from stream r usinbg the offcial CycloneDX
// libraries and returns a protobom document with its data.
func (u *UnserializerCDX14) ParseStream(_ *options.Options, r io.Reader) (*sbom.Document, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decoding cyclonedx: %w", err)
	}

	doc := &sbom.Document{
		Metadata: &sbom.Metadata{
			Id:      bom.SerialNumber,
			Version: fmt.Sprintf("%d", bom.Version),
			// Name:    ,
			Date:    &timestamppb.Timestamp{},
			Tools:   []*sbom.Tool{},
			Authors: []*sbom.Person{},
			// Comment: bom.Com,
		},
		NodeList: &sbom.NodeList{},
	}

	if bom.Metadata.Component != nil {
		nl, err := u.componentToNodeList(bom.Metadata.Component)
		if err != nil {
			return nil, fmt.Errorf("converting main bom component to node: %w", err)
		}
		if len(nl.RootElements) > 1 {
			logrus.Warnf("root nodelist has %d components, this should not happen", len(nl.RootElements))
		}
		doc.NodeList.Add(nl)
	}

	// Cycle all components and get their graph fragments
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

	return doc, nil
}

// componentToNodes takes a CycloneDX component and computes its graph fragment,
// returning a nodelist
func (u *UnserializerCDX14) componentToNodeList(component *cdx.Component) (*sbom.NodeList, error) {
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

func (u *UnserializerCDX14) componentToNode(c *cdx.Component) (*sbom.Node, error) { //nolint:unparam
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
		Identifiers:        []*sbom.Identifier{},
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
		er := &sbom.ExternalReference{
			Url:  c.CPE,
			Type: "cpe22",
		}
		if strings.HasPrefix(c.CPE, "cpe:2.3") {
			er.Type = "cpe23"
		}
		node.ExternalReferences = append(node.ExternalReferences, er)
	}

	if c.PackageURL != "" {
		node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
			Url:  c.PackageURL,
			Type: "purl",
		})
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
func (u *UnserializerCDX14) licenseChoicesToLicenseList(lcs *cdx.Licenses) []string {
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
func (u *UnserializerCDX14) licenseChoicesToLicenseString(lcs *cdx.Licenses) string {
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
