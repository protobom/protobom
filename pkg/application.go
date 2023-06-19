package pkg

import (
	"os"

	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"
	"github.com/bom-squad/protobom/pkg/writer/options"
	"github.com/sirupsen/logrus"
)

type Application struct {
	WriterOpts options.Options
}

func Translate(path string, cfg *Application) error {
	var doc *sbom.Document

	parser := reader.New()
	doc, err := parser.ParseFile(path)
	if err != nil {
		logrus.Fatalf("parsing file: %v", err)
		return err
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
	renderer.Options = cfg.WriterOpts

	// Serialize and render the protobom to STDOUT:
	if err := renderer.WriteStream(doc, os.Stdout); err != nil {
		logrus.Fatalf("writing sbom to stdout: %v", err)
		return err
	}

	return nil
}
