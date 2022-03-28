package resolvers

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

import (
	"github.com/hyperledger/fabric-gateway/pkg/client"
	clientmsp "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/kfsoftware/hlf-cc-dev/gql"
)

type Resolver struct {
	SDK           *fabsdk.FabricSDK
	GWClient      *client.Gateway
	SDKContext    context.ClientProvider
	SDKContextMap map[string]context.ClientProvider
	Channel       string
	MSPClient     *clientmsp.Client
	CAConfig      *msp.CAConfig
	Organization  string
	User          string
}

// Mutation returns gql.MutationResolver implementation.
func (r *Resolver) Mutation() gql.MutationResolver { return &mutationResolver{r} }

// Query returns gql.QueryResolver implementation.
func (r *Resolver) Query() gql.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }

type queryResolver struct{ *Resolver }
