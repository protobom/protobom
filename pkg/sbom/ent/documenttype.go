// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/bom-squad/protobom/pkg/sbom/ent/documenttype"
)

// DocumentType is the model entity for the DocumentType schema.
type DocumentType struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// Type holds the value of the "type" field.
	Type documenttype.Type `json:"type,omitempty"`
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty"`
	// Description holds the value of the "description" field.
	Description             string `json:"description,omitempty"`
	metadata_document_types *string
	selectValues            sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*DocumentType) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case documenttype.FieldID:
			values[i] = new(sql.NullInt64)
		case documenttype.FieldType, documenttype.FieldName, documenttype.FieldDescription:
			values[i] = new(sql.NullString)
		case documenttype.ForeignKeys[0]: // metadata_document_types
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the DocumentType fields.
func (dt *DocumentType) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case documenttype.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			dt.ID = int(value.Int64)
		case documenttype.FieldType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field type", values[i])
			} else if value.Valid {
				dt.Type = documenttype.Type(value.String)
			}
		case documenttype.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				dt.Name = value.String
			}
		case documenttype.FieldDescription:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field description", values[i])
			} else if value.Valid {
				dt.Description = value.String
			}
		case documenttype.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field metadata_document_types", values[i])
			} else if value.Valid {
				dt.metadata_document_types = new(string)
				*dt.metadata_document_types = value.String
			}
		default:
			dt.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the DocumentType.
// This includes values selected through modifiers, order, etc.
func (dt *DocumentType) Value(name string) (ent.Value, error) {
	return dt.selectValues.Get(name)
}

// Update returns a builder for updating this DocumentType.
// Note that you need to call DocumentType.Unwrap() before calling this method if this DocumentType
// was returned from a transaction, and the transaction was committed or rolled back.
func (dt *DocumentType) Update() *DocumentTypeUpdateOne {
	return NewDocumentTypeClient(dt.config).UpdateOne(dt)
}

// Unwrap unwraps the DocumentType entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (dt *DocumentType) Unwrap() *DocumentType {
	_tx, ok := dt.config.driver.(*txDriver)
	if !ok {
		panic("ent: DocumentType is not a transactional entity")
	}
	dt.config.driver = _tx.drv
	return dt
}

// String implements the fmt.Stringer.
func (dt *DocumentType) String() string {
	var builder strings.Builder
	builder.WriteString("DocumentType(")
	builder.WriteString(fmt.Sprintf("id=%v, ", dt.ID))
	builder.WriteString("type=")
	builder.WriteString(fmt.Sprintf("%v", dt.Type))
	builder.WriteString(", ")
	builder.WriteString("name=")
	builder.WriteString(dt.Name)
	builder.WriteString(", ")
	builder.WriteString("description=")
	builder.WriteString(dt.Description)
	builder.WriteByte(')')
	return builder.String()
}

// DocumentTypes is a parsable slice of DocumentType.
type DocumentTypes []*DocumentType