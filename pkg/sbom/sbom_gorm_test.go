// Unstable: The GORM models are currently in active development and their API is subject to change.
package sbom_test

import (
	"context"
	"fmt"

	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// Connection string for an in-memory SQLite3 database with foreign key support enabled.
const dsnString = ":memory:?_pragma=foreign_keys(1)"

var (
	ctx = context.Background()
	db  *gorm.DB
)

func Example() {
	var err error

	// Create database and initialize schema.
	db, err = gorm.Open(sqlite.Open(dsnString), &gorm.Config{})
	if err != nil {
		// Handle error.
	}

	models := []interface{}{
		&sbom.DocumentORM{},
		&sbom.DocumentTypeORM{},
		&sbom.EdgeORM{},
		&sbom.ExternalReferenceORM{},
		&sbom.MetadataORM{},
		&sbom.NodeListORM{},
		&sbom.NodeORM{},
		&sbom.PersonORM{},
		&sbom.ToolORM{},
	}

	// Create database tables from model definitions.
	for _, model := range models {
		err := db.AutoMigrate(model)
		if err != nil {
			// Handle error.
		}
	}

	sbomReader := reader.New()
	document, err := sbomReader.ParseFile("../../test/conformance/testdata/cyclonedx/1.5/json/bom-1.5.json")
	if err != nil {
		// Handle error.
	}

	// Convert Document to its ORM representation.
	documentORM, err := document.ToORM(ctx)
	if err != nil {
		// Handle error.
	}

	// Insert ORM Document into `documents` table.
	db.Create(&documentORM)

	// Get all nodes by node list ID.
	var nodes []*sbom.NodeORM
	db.Where(&sbom.NodeORM{NodeListId: &documentORM.NodeList.Id}).Find(&nodes)

	for _, node := range nodes {
		fmt.Printf("&sbom.NodeORM{Id: %s, Type: %d, Name: %s, Version: %s, LicenseConcluded: %s}\n", node.Id, node.Type, node.Name, node.Version, node.LicenseConcluded)
	}

	// Get all edges by node list ID.
	var edges []*sbom.EdgeORM
	db.Where(&sbom.EdgeORM{From: nodes[0].Id}).Find(&edges)

	for _, edge := range edges {
		fmt.Printf("&sbom.EdgeORM{Type: %d, From: %s, NodeListId: %d}\n", edge.Type, edge.From, *edge.NodeListId)
	}

	// Run query string against database.
	var result []*sbom.NodeORM
	db.Raw("SELECT * FROM nodes n INNER JOIN node_lists nl ON n.node_list_id = nl.id WHERE n.id = ?", nodes[0].Id).Scan(&result)
	for _, node := range result {
		fmt.Printf("&sbom.NodeORM{Id: %s, NodeListId: %d}\n", node.Id, *node.NodeListId)
	}

	// Output:
	// &sbom.NodeORM{Id: protobom-auto--000000001, Type: 0, Name: Acme Application, Version: 9.1.1, LicenseConcluded: }
	// &sbom.NodeORM{Id: pkg:npm/acme/component@1.0.0, Type: 0, Name: tomcat-catalina, Version: 9.0.14, LicenseConcluded: Apache-2.0}
	// &sbom.NodeORM{Id: protobom-auto--000000003, Type: 0, Name: mylibrary, Version: 1.0.0, LicenseConcluded: }
	// &sbom.EdgeORM{Type: 5, From: protobom-auto--000000001, NodeListId: 1}
	// &sbom.NodeORM{Id: 1, NodeListId: 1}
}
