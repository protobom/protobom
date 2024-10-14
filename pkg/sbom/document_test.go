package sbom_test

import "github.com/protobom/protobom/pkg/sbom"

// Demonstrates how to create a new protobom document and add multiple root nodes representing different software applications.
// Each root node has distinct properties such as ID, name, version, licenses, etc. These root nodes are then attached to the document.
func Example_roots() {
	// Create a new protobom document
	document := sbom.NewDocument()

	// Create a node to represent the application:
	firstRoot := &sbom.Node{
		Id:               "pkg:generic/my-software@v1.0.0",
		PrimaryPurpose:   []sbom.Purpose{sbom.Purpose_APPLICATION},
		Name:             "My Software Name",
		Version:          "v1.0.0",
		Licenses:         []string{"Apache-2.0"},
		LicenseConcluded: "Apache-2.0",
		LicenseComments:  "Apache License",
	}

	// Create a second node to represent the application,
	// It can have a eather the same or a different purpose.
	secondRoot := &sbom.Node{
		Id:               "pkg:generic/my-second-software@v2.0.0",
		PrimaryPurpose:   []sbom.Purpose{sbom.Purpose_DEVICE},
		Name:             "My Second Software Name",
		Version:          "v2.0.0",
		Licenses:         []string{"Apache-2.0"},
		LicenseConcluded: "Apache-2.0",
		LicenseComments:  "Apache License",
	}

	// Attach both roots to document
	document.NodeList.AddRootNode(firstRoot)
	document.NodeList.AddRootNode(secondRoot)
}

// Illustrates how to create a new protobom document and populate its metadata.
// It sets the document name, version, ID, author information, and the tool details that produced the SBOM.
func Example_metadata() {
	// Create a new protobom document
	document := sbom.NewDocument()

	// Populate some of the document metadata:
	document.Metadata.Name = "My software name"
	document.Metadata.Version = "v1.0.0"
	document.Metadata.Id = "acme_my_software_v0.1.0"

	// ...for example the author:
	document.Metadata.Authors = append(
		document.Metadata.Authors,
		&sbom.Person{Name: "John Doe"},
	)

	// ...and the tool that produced the SBOM:
	document.Metadata.Tools = append(
		document.Metadata.Tools,
		&sbom.Tool{
			Name:    "ACME SBOM Tool",
			Version: "1.0",
			Vendor:  "ACME Corporation",
		},
	)
}

// Showcases how to create a new protobom document, add nodes representing software components,
// create a build dependency edge between two software components, and attach these components to the document.
func Example_nodes() {
	// Create a new protobom document
	document := sbom.NewDocument()

	// Create a node to represent some software component:
	firstNode := &sbom.Node{
		Id:               "pkg:generic/my-software@v1.0.0",
		PrimaryPurpose:   []sbom.Purpose{sbom.Purpose_APPLICATION},
		Name:             "My Software Name",
		Version:          "v1.0.0",
		Licenses:         []string{"Apache-2.0"},
		LicenseConcluded: "Apache-2.0",
		LicenseComments:  "Apache License",
	}

	// Create a second node to represent a second software component
	secondSecond := &sbom.Node{
		Id:               "pkg:generic/my-second-software@v2.0.0",
		PrimaryPurpose:   []sbom.Purpose{sbom.Purpose_DEVICE},
		Name:             "My Second Software Name",
		Version:          "v2.0.0",
		Licenses:         []string{"Apache-2.0"},
		LicenseConcluded: "Apache-2.0",
		LicenseComments:  "Apache License",
	}

	// Create build dependency edge between the two software components.
	edge := &sbom.Edge{
		Type: sbom.Edge_buildDependency,
		From: "pkg:generic/my-software@v1.0.0",
		To: []string{
			"pkg:generic/my-second-software@v2.0.0",
		},
	}

	// Attach components to document
	document.NodeList.AddNode(firstNode)
	document.NodeList.AddNode(secondSecond)
	document.NodeList.AddEdge(edge)
}
