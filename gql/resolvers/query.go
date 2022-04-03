package resolvers

import (
	"context"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/kfsoftware/hlf-cc-dev/gql/models"
)

func (r *queryResolver) Chaincodes(ctx context.Context) ([]*models.Chaincode, error) {
	resClient, err := resmgmt.New(r.SDKContext)
	if err != nil {
		return nil, err
	}
	committedCCs, err := resClient.LifecycleQueryCommittedCC(r.Channel, resmgmt.LifecycleQueryCommittedCCRequest{})
	if err != nil {
		return nil, err
	}
	var chaincodes []*models.Chaincode
	for _, cc := range committedCCs {
		chaincodes = append(chaincodes, &models.Chaincode{
			Name:     cc.Name,
			Sequence: int(cc.Sequence),
			Version:  cc.Version,
		})
	}
	return chaincodes, nil
}

func (r *queryResolver) Chaincode(ctx context.Context, name string) (*models.Chaincode, error) {
	resClient, err := resmgmt.New(r.SDKContext)
	if err != nil {
		return nil, err
	}
	committedCCs, err := resClient.LifecycleQueryCommittedCC(r.Channel, resmgmt.LifecycleQueryCommittedCCRequest{
		Name: name,
	})
	if err != nil {
		return nil, err
	}
	var chaincode *models.Chaincode
	for _, cc := range committedCCs {
		chaincode = &models.Chaincode{
			Name:     cc.Name,
			Sequence: int(cc.Sequence),
			Version:  cc.Version,
		}
	}
	return chaincode, nil
}
