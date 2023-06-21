package writer

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer/options"
	"github.com/sirupsen/logrus"
)

type SerializerCDX struct{}

func (s *SerializerCDX) Serialize(opts options.Options, bom *sbom.Document) (interface{}, error) {
	doc := cdx.NewBOM()
	doc.SerialNumber = bom.Metadata.Id
	ver, err := strconv.Atoi(bom.Metadata.Version)
	if err == nil {
		doc.Version = ver
	}

	metadata := cdx.Metadata{
		// Tools:     []cdx14.Tool{},
		Component: &cdx.Component{},
	}

	doc.Metadata = &metadata
	doc.Components = &[]cdx.Component{}
	doc.Dependencies = &[]cdx.Dependency{}
	/*
		if bom.Metadata.Date != nil {
			doc.Metadata.Timestamp = bom.Metadata.Date.AsTime()
		}
	*/

	// Generate all components
	components := map[string]*cdx.Component{}
	refless := []*cdx.Component{}
	for _, n := range bom.NodeList.Nodes {
		comp := s.nodeToComponent(n)
		if comp == nil {
			// Error? Warn?
			continue
		}

		if comp.BOMRef == "" {
			refless = append(refless, comp)
		} else {
			components[comp.BOMRef] = comp
		}
	}

	rootDict := map[string]struct{}{}
	addedDict := map[string]struct{}{}

	// First, assign the top level nodes
	if bom.NodeList.RootElements != nil && len(bom.NodeList.RootElements) > 0 {
		for _, id := range bom.NodeList.RootElements {
			rootDict[id] = struct{}{}
			// Search for the node and add it
			for _, n := range bom.NodeList.Nodes {
				if n.Id == id {
					rootComp := s.nodeToComponent(n)
					doc.Metadata.Component = rootComp
					addedDict[id] = struct{}{}
				}
			}

			// TODO(degradation): Here we would document other root level elements
			// are not added to to document
			break
		}
	}

	// Next up. Let's navigate the SBOM graph and translate it to the CDX simpler
	// tree or to the dependency graph
	for _, e := range bom.NodeList.Edges {
		if _, ok := addedDict[e.From]; ok {
			continue
		}

		if _, ok := components[e.From]; !ok {
			logrus.Info("serialize")
			return nil, fmt.Errorf("unable to find component %s", e.From)
		}

		// In this example, we tree-ify all components related with a
		// "contains" relationship. This is just an opinion for the demo
		// and it is somethign we can parameterize
		switch e.Type {
		case sbom.Edge_contains:
			// Make sure we have the target component
			for _, targetID := range e.To {
				addedDict[targetID] = struct{}{}
				if _, ok := components[targetID]; !ok {
					return nil, fmt.Errorf("unable to locate node %s", targetID)
				}

				if components[e.From].Components == nil {
					components[e.From].Components = &[]cdx.Component{}
				}
				*components[e.From].Components = append(*components[e.From].Components, *components[targetID])
			}

		case sbom.Edge_dependsOn:
			// Add to the dependency tree
			for _, targetID := range e.To {
				addedDict[targetID] = struct{}{}
				if _, ok := components[targetID]; !ok {
					return nil, fmt.Errorf("unable to locate node %s", targetID)
				}

				if doc.Dependencies == nil {
					doc.Dependencies = &[]cdx.Dependency{}
				}

				*doc.Dependencies = append(*doc.Dependencies, cdx.Dependency{
					Ref:          e.From,
					Dependencies: &e.To,
				})
			}

		default:
			// TODO(degradation) here, we would document how relationships are lost
			logrus.Warnf(
				"node %s is related with %s to %d other nodes, data will be lost",
				e.From, e.Type, len(e.To),
			)
		}

		// Now add al nodes we have not yet positioned
		for _, c := range components {
			if _, ok := addedDict[c.BOMRef]; ok {
				continue
			}
			*doc.Components = append(*doc.Components, *c)
		}

		// Add components without refs
		for _, c := range refless {
			*doc.Components = append(*doc.Components, *c)
		}
	}
	return doc, nil
}

// nodeToComponent converts a node in protobuf to a CycloneDX component
func (s *SerializerCDX) nodeToComponent(n *sbom.Node) *cdx.Component {
	if n == nil {
		return nil
	}
	c := &cdx.Component{
		BOMRef:      n.Id,
		Type:        cdx.ComponentType(strings.ToLower(n.PrimaryPurpose)), // Fix to make it valid
		Name:        n.Name,
		Version:     n.Version,
		Description: n.Description,
		// Components:  []cdx14.Component{},
	}

	if n.Type == sbom.Node_FILE {
		c.Type = "file"
	}

	if n.Licenses != nil && len(n.Licenses) > 0 {
		var licenseChoices []cdx.LicenseChoice
		var licenses cdx.Licenses
		for _, l := range n.Licenses {
			licenseChoices = append(licenseChoices, cdx.LicenseChoice{
				License: &cdx.License{
					ID: l,
				},
			})
		}

		licenses = licenseChoices
		c.Licenses = &licenses
	}

	if n.Hashes != nil && len(n.Hashes) > 0 {
		c.Hashes = &[]cdx.Hash{}
		for algoString, hash := range n.Hashes {
			if algoVal, ok := sbom.HashAlgorithm_value[algoString]; ok {
				cdxAlgo := sbom.HashAlgorithm(algoVal).ToCycloneDX()
				if cdxAlgo == "" {
					// Data loss here.
					// TODO how do we handle when data loss occurs?
					continue
				}
				*c.Hashes = append(*c.Hashes, cdx.Hash{
					Algorithm: cdxAlgo,
					Value:     hash,
				})
			}
		}
	}

	if n.ExternalReferences != nil {
		for _, er := range n.ExternalReferences {
			if er.Type == "purl" {
				c.PackageURL = er.Url
				continue
			}

			if c.ExternalReferences == nil {
				c.ExternalReferences = &[]cdx.ExternalReference{}
			}

			*c.ExternalReferences = append(*c.ExternalReferences, cdx.ExternalReference{
				Type: cdx.ExternalReferenceType(er.Type), // Fix to make it valid
				URL:  er.Url,
			})
		}
	}

	return c
}

// renderVersion calls the official CDX serializer to render the BOM into a
// specific version
func (s *SerializerCDX) renderVersion(cdxVersion cdx.SpecVersion, doc interface{}, wr io.Writer) error {
	if doc == nil {
		return errors.New("no doc found")
	}

	encoder := cdx.NewBOMEncoder(wr, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)

	if err := encoder.EncodeVersion(doc.(*cdx.BOM), cdxVersion); err != nil {
		return fmt.Errorf("encoding sbom to stream: %w", err)
	}

	return nil
}
