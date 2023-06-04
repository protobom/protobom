package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

var filename = filepath.Join(os.TempDir(), "sbom.proto")

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

	// fmt.Printf("%+v", doc)

	// writeProto(doc)
	// doc = readProto()

	renderer := writer.New()

	if err := renderer.WriteStream(doc, os.Stdout); err != nil {
		logrus.Fatalf("writing sbom to stdout: %v", err)
	}
}

func writeProto(bom *sbom.Document) {
	out, err := proto.Marshal(bom)
	if err != nil {
		logrus.Fatal("marshalling sbom to protobuf: %v", err)
	}

	if err := os.WriteFile(filename, out, os.FileMode(0o644)); err != nil {
		logrus.Fatal("writing data to disk: %v", err)
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
