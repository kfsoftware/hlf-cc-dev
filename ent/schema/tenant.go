package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Tenant holds the schema definition for the Tenant entity.
type Tenant struct {
	ent.Schema
}

// Fields of the Tenant.
func (Tenant) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").Unique(),
		field.String("mspId"),
		field.Bytes("signCertCAPrivateKey").Optional(),
		field.Bytes("signCertCACert").Optional(),
		field.Bytes("tlsCertCAPrivateKey").Optional(),
		field.Bytes("tlsCertCACert").Optional(),
	}
}

// Edges of the Tenant.
func (Tenant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("chaincodes", Chaincode.Type),
	}
}
