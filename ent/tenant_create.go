// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/kfsoftware/hlf-cc-dev/ent/chaincode"
	"github.com/kfsoftware/hlf-cc-dev/ent/tenant"
)

// TenantCreate is the builder for creating a Tenant entity.
type TenantCreate struct {
	config
	mutation *TenantMutation
	hooks    []Hook
}

// SetName sets the "name" field.
func (tc *TenantCreate) SetName(s string) *TenantCreate {
	tc.mutation.SetName(s)
	return tc
}

// SetMspId sets the "mspId" field.
func (tc *TenantCreate) SetMspId(s string) *TenantCreate {
	tc.mutation.SetMspId(s)
	return tc
}

// SetSignCertCAPrivateKey sets the "signCertCAPrivateKey" field.
func (tc *TenantCreate) SetSignCertCAPrivateKey(b []byte) *TenantCreate {
	tc.mutation.SetSignCertCAPrivateKey(b)
	return tc
}

// SetSignCertCACert sets the "signCertCACert" field.
func (tc *TenantCreate) SetSignCertCACert(b []byte) *TenantCreate {
	tc.mutation.SetSignCertCACert(b)
	return tc
}

// SetTlsCertCAPrivateKey sets the "tlsCertCAPrivateKey" field.
func (tc *TenantCreate) SetTlsCertCAPrivateKey(b []byte) *TenantCreate {
	tc.mutation.SetTlsCertCAPrivateKey(b)
	return tc
}

// SetTlsCertCACert sets the "tlsCertCACert" field.
func (tc *TenantCreate) SetTlsCertCACert(b []byte) *TenantCreate {
	tc.mutation.SetTlsCertCACert(b)
	return tc
}

// AddChaincodeIDs adds the "chaincodes" edge to the Chaincode entity by IDs.
func (tc *TenantCreate) AddChaincodeIDs(ids ...int) *TenantCreate {
	tc.mutation.AddChaincodeIDs(ids...)
	return tc
}

// AddChaincodes adds the "chaincodes" edges to the Chaincode entity.
func (tc *TenantCreate) AddChaincodes(c ...*Chaincode) *TenantCreate {
	ids := make([]int, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return tc.AddChaincodeIDs(ids...)
}

// Mutation returns the TenantMutation object of the builder.
func (tc *TenantCreate) Mutation() *TenantMutation {
	return tc.mutation
}

// Save creates the Tenant in the database.
func (tc *TenantCreate) Save(ctx context.Context) (*Tenant, error) {
	var (
		err  error
		node *Tenant
	)
	if len(tc.hooks) == 0 {
		if err = tc.check(); err != nil {
			return nil, err
		}
		node, err = tc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*TenantMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = tc.check(); err != nil {
				return nil, err
			}
			tc.mutation = mutation
			if node, err = tc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(tc.hooks) - 1; i >= 0; i-- {
			if tc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = tc.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, tc.mutation); err != nil {
			return nil, err
		}
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (tc *TenantCreate) SaveX(ctx context.Context) *Tenant {
	v, err := tc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (tc *TenantCreate) Exec(ctx context.Context) error {
	_, err := tc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tc *TenantCreate) ExecX(ctx context.Context) {
	if err := tc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (tc *TenantCreate) check() error {
	if _, ok := tc.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`ent: missing required field "name"`)}
	}
	if _, ok := tc.mutation.MspId(); !ok {
		return &ValidationError{Name: "mspId", err: errors.New(`ent: missing required field "mspId"`)}
	}
	return nil
}

func (tc *TenantCreate) sqlSave(ctx context.Context) (*Tenant, error) {
	_node, _spec := tc.createSpec()
	if err := sqlgraph.CreateNode(ctx, tc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{err.Error(), err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (tc *TenantCreate) createSpec() (*Tenant, *sqlgraph.CreateSpec) {
	var (
		_node = &Tenant{config: tc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: tenant.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: tenant.FieldID,
			},
		}
	)
	if value, ok := tc.mutation.Name(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: tenant.FieldName,
		})
		_node.Name = value
	}
	if value, ok := tc.mutation.MspId(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: tenant.FieldMspId,
		})
		_node.MspId = value
	}
	if value, ok := tc.mutation.SignCertCAPrivateKey(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeBytes,
			Value:  value,
			Column: tenant.FieldSignCertCAPrivateKey,
		})
		_node.SignCertCAPrivateKey = value
	}
	if value, ok := tc.mutation.SignCertCACert(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeBytes,
			Value:  value,
			Column: tenant.FieldSignCertCACert,
		})
		_node.SignCertCACert = value
	}
	if value, ok := tc.mutation.TlsCertCAPrivateKey(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeBytes,
			Value:  value,
			Column: tenant.FieldTlsCertCAPrivateKey,
		})
		_node.TlsCertCAPrivateKey = value
	}
	if value, ok := tc.mutation.TlsCertCACert(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeBytes,
			Value:  value,
			Column: tenant.FieldTlsCertCACert,
		})
		_node.TlsCertCACert = value
	}
	if nodes := tc.mutation.ChaincodesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   tenant.ChaincodesTable,
			Columns: []string{tenant.ChaincodesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: chaincode.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// TenantCreateBulk is the builder for creating many Tenant entities in bulk.
type TenantCreateBulk struct {
	config
	builders []*TenantCreate
}

// Save creates the Tenant entities in the database.
func (tcb *TenantCreateBulk) Save(ctx context.Context) ([]*Tenant, error) {
	specs := make([]*sqlgraph.CreateSpec, len(tcb.builders))
	nodes := make([]*Tenant, len(tcb.builders))
	mutators := make([]Mutator, len(tcb.builders))
	for i := range tcb.builders {
		func(i int, root context.Context) {
			builder := tcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*TenantMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, tcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, tcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{err.Error(), err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, tcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (tcb *TenantCreateBulk) SaveX(ctx context.Context) []*Tenant {
	v, err := tcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (tcb *TenantCreateBulk) Exec(ctx context.Context) error {
	_, err := tcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tcb *TenantCreateBulk) ExecX(ctx context.Context) {
	if err := tcb.Exec(ctx); err != nil {
		panic(err)
	}
}
