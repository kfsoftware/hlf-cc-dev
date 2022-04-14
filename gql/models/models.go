// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package models

type Chaincode struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Sequence int    `json:"sequence"`
}

type CouchDBIndex struct {
	ID       string `json:"id"`
	Contents string `json:"contents"`
}

type CreateTenantInput struct {
	Name string      `json:"name"`
	Orgs []*OrgInput `json:"orgs"`
}

type DeployChaincodeInput struct {
	Name             string          `json:"name"`
	Pdc              string          `json:"pdc"`
	ChaincodeAddress string          `json:"chaincodeAddress"`
	SignaturePolicy  string          `json:"signaturePolicy"`
	Indexes          []*CouchDBIndex `json:"indexes"`
	Channel          string          `json:"channel"`
}

type DeployChaincodeResponse struct {
	PackageID       string `json:"packageID"`
	Version         string `json:"version"`
	Sequence        int    `json:"sequence"`
	ChaincodeName   string `json:"chaincodeName"`
	PrivateKey      string `json:"privateKey"`
	Certificate     string `json:"certificate"`
	RootCertificate string `json:"rootCertificate"`
	ChannelName     string `json:"channelName"`
}

type InvokeChaincodeInput struct {
	Channel       *string              `json:"channel"`
	ChaincodeName string               `json:"chaincodeName"`
	Function      string               `json:"function"`
	Args          []string             `json:"args"`
	TransientMap  []*TransientArgument `json:"transientMap"`
}

type InvokeChaincodeResponse struct {
	Response        string `json:"response"`
	TransactionID   string `json:"transactionID"`
	ChaincodeStatus int    `json:"chaincodeStatus"`
}

type OrgInput struct {
	Name  string `json:"name"`
	MspID string `json:"mspID"`
}

type QueryChaincodeInput struct {
	Channel       *string              `json:"channel"`
	ChaincodeName string               `json:"chaincodeName"`
	Function      string               `json:"function"`
	Args          []string             `json:"args"`
	TransientMap  []*TransientArgument `json:"transientMap"`
}

type QueryChaincodeResponse struct {
	Response        string `json:"response"`
	ChaincodeStatus int    `json:"chaincodeStatus"`
}

type Tenant struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	MspID string `json:"mspId"`
}

type TransientArgument struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
