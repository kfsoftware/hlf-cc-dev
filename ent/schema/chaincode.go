package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Chaincode holds the schema definition for the Chaincode entity.
type Chaincode struct {
	ent.Schema
}

// Fields of the Chaincode.
func (Chaincode) Fields() []ent.Field {
	return []ent.Field{
		field.String("packageId").NotEmpty(),
		field.String("channelId"),
	}
}

// Edges of the Chaincode.
func (Chaincode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("chaincodes").
			Unique(),
	}
}
