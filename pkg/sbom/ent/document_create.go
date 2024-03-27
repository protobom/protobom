// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/bom-squad/protobom/pkg/sbom/ent/document"
	"github.com/bom-squad/protobom/pkg/sbom/ent/metadata"
	"github.com/bom-squad/protobom/pkg/sbom/ent/nodelist"
)

// DocumentCreate is the builder for creating a Document entity.
type DocumentCreate struct {
	config
	mutation *DocumentMutation
	hooks    []Hook
}

// AddMetadatumIDs adds the "metadata" edge to the Metadata entity by IDs.
func (dc *DocumentCreate) AddMetadatumIDs(ids ...string) *DocumentCreate {
	dc.mutation.AddMetadatumIDs(ids...)
	return dc
}

// AddMetadata adds the "metadata" edges to the Metadata entity.
func (dc *DocumentCreate) AddMetadata(m ...*Metadata) *DocumentCreate {
	ids := make([]string, len(m))
	for i := range m {
		ids[i] = m[i].ID
	}
	return dc.AddMetadatumIDs(ids...)
}

// AddNodeListIDs adds the "node_list" edge to the NodeList entity by IDs.
func (dc *DocumentCreate) AddNodeListIDs(ids ...int) *DocumentCreate {
	dc.mutation.AddNodeListIDs(ids...)
	return dc
}

// AddNodeList adds the "node_list" edges to the NodeList entity.
func (dc *DocumentCreate) AddNodeList(n ...*NodeList) *DocumentCreate {
	ids := make([]int, len(n))
	for i := range n {
		ids[i] = n[i].ID
	}
	return dc.AddNodeListIDs(ids...)
}

// Mutation returns the DocumentMutation object of the builder.
func (dc *DocumentCreate) Mutation() *DocumentMutation {
	return dc.mutation
}

// Save creates the Document in the database.
func (dc *DocumentCreate) Save(ctx context.Context) (*Document, error) {
	return withHooks(ctx, dc.sqlSave, dc.mutation, dc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (dc *DocumentCreate) SaveX(ctx context.Context) *Document {
	v, err := dc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dc *DocumentCreate) Exec(ctx context.Context) error {
	_, err := dc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dc *DocumentCreate) ExecX(ctx context.Context) {
	if err := dc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (dc *DocumentCreate) check() error {
	return nil
}

func (dc *DocumentCreate) sqlSave(ctx context.Context) (*Document, error) {
	if err := dc.check(); err != nil {
		return nil, err
	}
	_node, _spec := dc.createSpec()
	if err := sqlgraph.CreateNode(ctx, dc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	dc.mutation.id = &_node.ID
	dc.mutation.done = true
	return _node, nil
}

func (dc *DocumentCreate) createSpec() (*Document, *sqlgraph.CreateSpec) {
	var (
		_node = &Document{config: dc.config}
		_spec = sqlgraph.NewCreateSpec(document.Table, sqlgraph.NewFieldSpec(document.FieldID, field.TypeInt))
	)
	if nodes := dc.mutation.MetadataIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   document.MetadataTable,
			Columns: []string{document.MetadataColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(metadata.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := dc.mutation.NodeListIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   document.NodeListTable,
			Columns: []string{document.NodeListColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(nodelist.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// DocumentCreateBulk is the builder for creating many Document entities in bulk.
type DocumentCreateBulk struct {
	config
	err      error
	builders []*DocumentCreate
}

// Save creates the Document entities in the database.
func (dcb *DocumentCreateBulk) Save(ctx context.Context) ([]*Document, error) {
	if dcb.err != nil {
		return nil, dcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(dcb.builders))
	nodes := make([]*Document, len(dcb.builders))
	mutators := make([]Mutator, len(dcb.builders))
	for i := range dcb.builders {
		func(i int, root context.Context) {
			builder := dcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*DocumentMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, dcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, dcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, dcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (dcb *DocumentCreateBulk) SaveX(ctx context.Context) []*Document {
	v, err := dcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dcb *DocumentCreateBulk) Exec(ctx context.Context) error {
	_, err := dcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dcb *DocumentCreateBulk) ExecX(ctx context.Context) {
	if err := dcb.Exec(ctx); err != nil {
		panic(err)
	}
}