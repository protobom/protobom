package writer

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer/options"

	cdx14 "github.com/CycloneDX/cyclonedx-go"
	"github.com/sirupsen/logrus"
)

// SerializerCDX14 is an object that writes a protobuf sbom to CycloneDX 1.4
// This is not using the official CDX libraries but a library of another project
// that has the CDX type. We should probably switch to the real CDX libs.
type SerializerCDX14 struct{}

func (s *SerializerCDX14) Serialize(opts options.Options, bom *sbom.Document) (interface{}, error) {
	doc := cdx14.NewBOM()
	doc.SerialNumber = bom.Metadata.Id
	ver, err := strconv.Atoi(bom.Metadata.Version)
	if err == nil {
		doc.Version = ver
	}

	metadata := cdx14.Metadata{
		// Tools:     []cdx14.Tool{},
		Component: &cdx14.Component{},
	}

	doc.Metadata = &metadata
	doc.Components = &[]cdx14.Component{}
	doc.Dependencies = &[]cdx14.Dependency{}
	/*
		if bom.Metadata.Date != nil {
			doc.Metadata.Timestamp = bom.Metadata.Date.AsTime()
		}
	*/

	// Generate all components
	components := map[string]*cdx14.Component{}
	refless := []*cdx14.Component{}
	for _, n := range bom.Nodes {
		comp := nodeToCDX14Component(n)
		if comp == nil {
			// Erorr? Warrn?
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
	if bom.RootElements != nil && len(bom.RootElements) > 0 {
		for _, id := range bom.RootElements {
			rootDict[id] = struct{}{}
			// Search for the node and add it
			for _, n := range bom.Nodes {
				if n.Id == id {
					rootComp := nodeToCDX14Component(n)
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
	for _, e := range bom.Edges {
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
					components[e.From].Components = &[]cdx14.Component{}
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
					doc.Dependencies = &[]cdx14.Dependency{}
				}

				*doc.Dependencies = append(*doc.Dependencies, cdx14.Dependency{
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

func (s *SerializerCDX14) Render(opts options.Options, doc interface{}, wr io.Writer) error {
	logrus.Debug("Writing SBOM in CycloneDX to STDOUT")
	encoder := cdx14.NewBOMEncoder(wr, cdx14.BOMFileFormatJSON)
	if doc == nil {
		return fmt.Errorf("no doc found")
	}

	if opts.Format.Type() != formats.CDXFROMAT {
		return fmt.Errorf("unsupported options, %v", opts)
	}

	encoder.SetPretty(true)

	cdxVersion := cdx14.SpecVersion1_4
	// 2DO - not sure if we should implicit switch case the suppported version or simply transform
	verMinor := opts.Format.Minor()
	ver, err := strconv.Atoi(verMinor)
	if err == nil {
		cdxVersion = cdx14.SpecVersion(ver)
	}

	err = encoder.EncodeVersion(doc.(*cdx14.BOM), cdxVersion)
	if err != nil {
		return fmt.Errorf("encoding sbom to stream: %w", err)
	}

	return nil
}

// nodeTo14Component converta a node in protobuf to a CycloneDX 1.4 component
func nodeToCDX14Component(n *sbom.Node) *cdx14.Component {
	if n == nil {
		return nil
	}
	c := &cdx14.Component{
		BOMRef:      n.Id,
		Type:        cdx14.ComponentType(strings.ToLower(n.PrimaryPurpose)), // Fix to make it valid
		Name:        n.Name,
		Version:     n.Version,
		Description: n.Description,
		// Components:  []cdx14.Component{},
	}

	if n.Type == sbom.Node_FILE {
		c.Type = "file"
	}

	if n.Licenses != nil && len(n.Licenses) > 0 {
		var licenseChoices []cdx14.LicenseChoice
		var licenses cdx14.Licenses
		for _, l := range n.Licenses {
			licenseChoices = append(licenseChoices, cdx14.LicenseChoice{
				License: &cdx14.License{
					ID: l,
				},
			})
		}

		licenses = licenseChoices
		c.Licenses = &licenses
	}

	if n.Hashes != nil && len(n.Hashes) > 0 {
		c.Hashes = &[]cdx14.Hash{}
		for algo, hash := range n.Hashes {
			*c.Hashes = append(*c.Hashes, cdx14.Hash{
				Algorithm: NormalizeAlgo(algo), // Fix to make it valid
				Value:     hash,
			})
		}
	}

	if n.ExternalReferences != nil {
		for _, er := range n.ExternalReferences {
			if er.Type == "purl" {
				c.PackageURL = er.Url
				continue
			}

			if c.ExternalReferences == nil {
				c.ExternalReferences = &[]cdx14.ExternalReference{}
			}

			*c.ExternalReferences = append(*c.ExternalReferences, cdx14.ExternalReference{
				Type: cdx14.ExternalReferenceType(er.Type), // Fix to make it valid
				URL:  er.Url,
			})
		}
	}

	return c
}

func NormalizeAlgo(algo string) cdx14.HashAlgorithm {
	agloNum := sbom.HashAlgorithm_value[algo]
	switch sbom.HashAlgorithm(agloNum) {
	case sbom.HashAlgorithm_MD5:
		return cdx14.HashAlgoMD5
	case sbom.HashAlgorithm_SHA1:
		return cdx14.HashAlgoSHA1
	case sbom.HashAlgorithm_SHA256:
		return cdx14.HashAlgoSHA256
	case sbom.HashAlgorithm_SHA384:
		return cdx14.HashAlgoSHA384
	case sbom.HashAlgorithm_SHA512:
		return cdx14.HashAlgoSHA512
	case sbom.HashAlgorithm_SHA3_256:
		return cdx14.HashAlgoSHA3_256
	case sbom.HashAlgorithm_SHA3_384:
		return cdx14.HashAlgoSHA3_384
	case sbom.HashAlgorithm_SHA3_512:
		return cdx14.HashAlgoBlake2b_256
	case sbom.HashAlgorithm_BLAKE2B_256:
		return cdx14.HashAlgoBlake2b_256
	case sbom.HashAlgorithm_BLAKE2B_384:
		return cdx14.HashAlgoBlake2b_384
	case sbom.HashAlgorithm_BLAKE2B_512:
		return cdx14.HashAlgoBlake2b_512
	case sbom.HashAlgorithm_BLAKE3:
		return cdx14.HashAlgoBlake3
	// case sbom.HashAlgorithm_MD2:
	// 	return "", fmt.Errorf("unsupported algo %s", algo) // What should we do ?
	// case sbom.HashAlgorithm_ADLER32:
	// 	return "", fmt.Errorf("unsupported algo %s", algo) // What should we do ?
	// case sbom.HashAlgorithm_MD4:
	// 	return "", fmt.Errorf("unsupported algo %s", algo) // What should we do ?
	// case sbom.HashAlgorithm_MD6:
	// 	return "", fmt.Errorf("unsupported algo %s", algo) // What should we do ?
	// case sbom.HashAlgorithm_SHA224:
	// 	return "", fmt.Errorf("unsupported algo %s", algo) // What should we do ?
	// case sbom.HashAlgorithm_UNKNOWN:
	// 	return "", fmt.Errorf("unknown algo %s", algo) // What should we do ?
	default:
		return cdx14.HashAlgorithm(algo) // 2DO ?
	}
}
