# protobom

`protobom` is a [protocol buffers](https://protobuf.dev/getting-started/)
representation of SBOM data able to ingest documents in modern
[SPDX](https://spdx.dev/) and [CycloneDX](https://cyclonedx.org/) versions
without loss. It has an accompanying Go library generated from the protocol
buffers definiton that also implements ingesters for those formats.

Standard SBOMs are read by a reader using [parsers](docs/parsers.md) that
understand the common formats. Parsers create a neutral protobom from data
read from CycloneDX or SPDX documents.

A protobom can be rendered into standard SBOM formats by the writer using
[serializers](docs/serializers.md) that know how to generate those documents.

## Supported Versions and Formats

The following table summarizes the current support for formats and encodings in
the golang library.

| Format | Version | Encoding | Read | Write |
| --- | --- | --- | --- | --- |
| SPDX | 2.2 | JSON | planned | - |
| SPDX | 2.2 | tag-value | planned | - |
| SPDX | 2.3 | JSON | supported | supported|
| SPDX | 2.3 | tag-value | planned | - |
| SPDX | 3.0 | JSON | planned | planned |
| CycloneDX | 1.4 | JSON | supported | supported |
| CycloneDX | 1.5 | JSON | planned | planned |

Other read and write implementations can potentially be written in
other [languages supported by protobuf](https://protobuf.dev/getting-started/)

## Usage

The `protobom` library can be used to read in and write out SBOM documents in any of the above formats.  

### Example 1:  The sbom-convert project

https://github.com/bom-squad/sbom-convert provides a complete example of using the library to ingest an SBOM into the protobom intermediate format and then write out a new SBOM document in a different format.

### Example 2:  Read in SBOM document to work with specific field(s)

The `protobom` library is the best and easiest way to interact with SBOM documents using the Go programming language.  In this example, we show how to easily access the SBOM programmatically by creating a new protobom `Reader`, and calling `reader.ParseFile()` to read an SBOM document file and return a protobom sbom.Document.  In this example, protobom handles the document unserialization regardless of the format.  The developer using protobom can be then work with a consistent protobom intermediate representation with the actual file format abstracted away.

This particular example iterates over each node of the SBOM document's list of nodes and prints the ID, Name, and Version of each node.  If the input document is an SPDX SBOM, each protobom Node will describe a single SPDX package.  If the input document is a CycloneDX SBOM, each protobom Node will describe a CycloneDX component.  The developer using protobom does not need to change the code based on the input format.  The protobom library parses the input document to present an intermediate format of the data allowing the developer to work with a consistent intermediate format instead.

```
package main

import (
	"fmt"

	"github.com/bom-squad/protobom/pkg/reader"
)

func main() {

	reader := reader.New()
	document, err := reader.ParseFile("sbom.spdx.json")
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}

	if document.GetNodeList() == nil {
		fmt.Printf("No Nodelist\n")
		return
	}

	for _, node := range document.GetNodeList().GetNodes() {
		fmt.Printf("Node ID [%v]: %v version %v\n", node.GetId(), node.GetName(), node.GetVersion())
	}
}
```

### Example 3:  Generate an SBOM document programmatically

Developers can use the `protobom` library to generate SBOM documents based on the content of a separate SBOM document, as shown by the sbom-convert project (https://github.com/bom-squad/sbom-convert).

However, the `protobom` intermediate representation could also be used to create a new SBOM document.  Developers could create a new `protobom` document and use the Go programming language to populate the fields needed in the SBOM document.  The developer would then create a new Writer to define where the SBOM should be written, to which format the SBOM should be written (default is CycloneDX 1.4), and call WriteStream() passing in the programmatically-defined SBOM structure.  

```
package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"
)

func main() {

	document := sbom.NewDocument()
	document.Metadata.Authors = append(document.Metadata.Authors, &sbom.Person{Name: "John Doe"})
	document.Metadata.Tools = append(document.Metadata.Tools,
		&sbom.Tool{Name: "ACME SBOM Tool", Version: "1.0", Vendor: "ACME Corporation"})

	metadata_node := &sbom.Node{
		Id:             "pkg:my-software@v1.0.0",
		PrimaryPurpose: "application",
		Name:           "My Software Name",
	}

	document.NodeList.AddNode(metadata_node)
	document.NodeList.RootElements = append(document.NodeList.RootElements, metadata_node.Id)

	node1 := &sbom.Node{
		Id:               "File--usr-lib-libsoftware.so",
		Type:             sbom.Node_FILE,
		Name:             "/usr/lib/libsoftware.so",
		Version:          "1",
		FileName:         "libsoftware.so",
		Licenses:         []string{"Apache-2.0"},
		LicenseConcluded: "Apache-2.0",
		LicenseComments:  "Apache License",
		Copyright:        "Copyright 2023 The ACME Corporation",
		Description:      "Software Lib",
	}

	hashes := make(map[int32]string)
	hashes[int32(sbom.HashAlgorithm_SHA1)] = "f3ae11065cafc14e27a1410ae8be28e600bb8336"
	hashes[int32(sbom.HashAlgorithm_SHA256)] = "4f232eeb99e1663d07f0af1af6ea262bf594934b694228e71fd8f159f9a19f32"
	hashes[int32(sbom.HashAlgorithm_SHA512)] = "8044d0df34242699ad73bfe99b9ac3d6bbdaa4f8ebce1e23ee5c7f9fe59db8ad7b01fe94e886941793aee802008a35b05a30bc51426db796aa21e5e91b7ed9be"
	node1.Hashes = hashes

	document.NodeList.AddNode(node1)

	node2 := &sbom.Node{
		Id:               "File--usr-bin-software",
		Type:             sbom.Node_FILE,
		Name:             "/usr/lib/software",
		Version:          "1",
		FileName:         "software",
		Licenses:         []string{"Apache-2.0"},
		LicenseConcluded: "Apache-2.0",
		LicenseComments:  "Apache License",
		Copyright:        "Copyright 2023 The ACME Corporation",
		Description:      "Software binary",
	}

	hashes = make(map[int32]string)
	hashes[int32(sbom.HashAlgorithm_SHA1)] = "defee82004d22fc92ab81c0c952a62a2172bda8c"
	hashes[int32(sbom.HashAlgorithm_SHA256)] = "ad291c9572af8fc2ec8fd78d295adf7132c60ad3d10488fb63d120fc967a4132"
	hashes[int32(sbom.HashAlgorithm_SHA512)] = "5940d8647907831e77ec00d81b318ca06655dbb0fd36d112684b03947412f0f98ea85b32548bc0877f3d7ce8f4de9b2c964062df44742b98c8e9bd851faecce9"
	node2.Hashes = hashes

	document.NodeList.AddNode(node2)

	file, err := os.CreateTemp("", "*.cdx.json")
	if err != nil {
		return
	}

	w := writer.New()
	err = w.WriteStream(document, file)

	if err != nil {
		fmt.Printf("error serializing SBOM, err %v\n", err)
		return
	} else {
		fmt.Printf("Created SBOM as %s\n", file.Name())
	}

	content, err := ioutil.ReadFile(file.Name())
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	// Display the file content to stdout
	fmt.Println(string(content))

}
```
