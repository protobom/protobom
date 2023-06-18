package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

var filename = filepath.Join(os.TempDir(), "sbom.proto")

// NOTICE:
// This program is a demo to test the protobom functions while
// we have a proper CLI and tests. It can be run directly.
// It expects an SBOM as its first argument and it will perform
// some tricks based on the following lines. See comments below

func main() {
	if len(os.Args) != 2 {
		logrus.Fatalf("usage: %s sbom.json", os.Args[0])
	}

	var doc *sbom.Document

	parser := reader.New()
	doc, err := parser.ParseFile(os.Args[1])
	if err != nil {
		logrus.Fatalf("parsing file: %v", err)
	}

	// Uncomment this to see a dump of the protobom go struct
	// fmt.Printf("%+v", doc)

	// Uncomment the following line to write the raw protobuf output
	// to the path in `filename` (defined above):
	// writeProto(doc)

	// If you have the raw protobuf written in `filename` (defined above)
	// you can re-read the doc variable from its contents by uncommenting
	// the following line:
	// doc = readProto()

	// Create a new renderer
	renderer := writer.New()

	// The SBOM read will be rewritten to the following format:
	// renderer.Options.Format = formats.CDX14JSON
	renderer.Options.Format = formats.CDX14JSON

	// Serialize and render the protobom to STDOUT:
	if err := renderer.WriteStream(doc, os.Stdout); err != nil {
		logrus.Fatalf("writing sbom to stdout: %v", err)
	}
}

func writeProto(bom *sbom.Document) {
	out, err := proto.Marshal(bom)
	if err != nil {
		logrus.Fatalf("marshalling sbom to protobuf: %v", err)
	}

	if err := os.WriteFile(filename, out, os.FileMode(0o644)); err != nil {
		logrus.Fatalf("writing data to disk: %v", err)
	}
}

func readProto() *sbom.Document {
	data, err := os.ReadFile(filename)
	if err != nil {
		logrus.Fatal(fmt.Errorf("reading proto data: %v", err))
	}
	bom := &sbom.Document{}
	if err := proto.Unmarshal(data, bom); err != nil {
		logrus.Fatal(fmt.Errorf("unmarshaling protobuf: %v", err))
	}
	return bom
}
