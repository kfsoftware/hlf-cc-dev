package resolvers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gosimple/slug"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	clientmsp "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/lifecycle"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/common/policydsl"
	"github.com/kfsoftware/hlf-cc-dev/gql/models"
	"github.com/kfsoftware/hlf-cc-dev/log"
	"github.com/lithammer/shortuuid/v3"
	"github.com/pkg/errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

func getChaincodePackage(label string, codeTarGz []byte) ([]byte, error) {
	var err error
	metadataJson := fmt.Sprintf(`
{
  "type": "external",
  "label": "%s"
}
`, label)
	// set up the output file
	buf := &bytes.Buffer{}

	// set up the gzip writer
	gw := gzip.NewWriter(buf)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	header := new(tar.Header)
	header.Name = "metadata.json"
	metadataJsonBytes := []byte(metadataJson)
	header.Size = int64(len(metadataJsonBytes))
	header.Mode = 0777
	err = tw.WriteHeader(header)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(metadataJsonBytes)
	_, err = io.Copy(tw, r)
	if err != nil {
		return nil, err
	}

	headerCode := new(tar.Header)
	headerCode.Name = "code.tar.gz"
	headerCode.Size = int64(len(codeTarGz))
	headerCode.Mode = 0777
	err = tw.WriteHeader(headerCode)
	if err != nil {
		return nil, err
	}
	r = bytes.NewReader(codeTarGz)
	_, err = io.Copy(tw, r)
	if err != nil {
		return nil, err
	}
	tw.Close()
	gw.Close()
	return buf.Bytes(), nil
}

func getCodeTarGz(address string, rootCert string, clientKey string, clientCert string, couchDBIndices []*models.CouchDBIndex) ([]byte, error) {
	var err error
	connMap := map[string]interface{}{
		"address":              address,
		"dial_timeout":         "10s",
		"tls_required":         true,
		"root_cert":            rootCert,
		"client_auth_required": true,
		"client_key":           clientKey,
		"client_cert":          clientCert,
	}
	connJsonBytes, err := json.Marshal(connMap)
	if err != nil {
		return nil, err
	}
	log.Infof("Conn=%s", string(connJsonBytes))
	// set up the output file
	buf := &bytes.Buffer{}

	// set up the gzip writer
	gw := gzip.NewWriter(buf)

	tw := tar.NewWriter(gw)
	header := new(tar.Header)
	header.Name = "connection.json"
	header.Size = int64(len(connJsonBytes))
	header.Mode = 0755
	err = tw.WriteHeader(header)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(connJsonBytes)
	_, err = io.Copy(tw, r)
	if err != nil {
		return nil, err
	}
	if len(couchDBIndices) > 0 {
		for _, couchDBIndex := range couchDBIndices {
			header := new(tar.Header)
			contentsBytes := []byte(couchDBIndex.Contents)
			header.Mode = 0755
			header.Size = int64(len(contentsBytes))
			header.Name = "META-INF/statedb/couchdb/indexes/" + couchDBIndex.ID
			// write header
			if err := tw.WriteHeader(header); err != nil {
				return nil, err
			}
			// if not a dir, write file content
			r := bytes.NewReader(contentsBytes)
			if _, err := io.Copy(tw, r); err != nil {
				return nil, err
			}
		}

	}

	tw.Close()
	gw.Close()
	return buf.Bytes(), nil
}

type mspFilter struct {
	mspID string
}

// Accept returns true if this peer is to be included in the target list
func (f *mspFilter) Accept(peer fab.Peer) bool {
	return peer.MSPID() == f.mspID
}
func (m mutationResolver) DeployChaincode(ctx context.Context, input models.DeployChaincodeInput) (*models.DeployChaincodeResponse, error) {
	chaincodeName := slug.Make(input.Name)
	address := input.ChaincodeAddress
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	userName := fmt.Sprintf("%s-%s", "chaincode", shortuuid.New()[:5])
	secret := shortuuid.New()
	_, err = m.MSPClient.Register(&clientmsp.RegistrationRequest{
		Name:           userName,
		Type:           "client",
		MaxEnrollments: -1,
		CAName:         m.CAConfig.CAName,
		Secret:         secret,
	})
	if err != nil && !strings.Contains(err.Error(), "is already registered") {
		return nil, err
	}
	err = m.MSPClient.Enroll(
		userName,
		clientmsp.WithSecret(secret),
		clientmsp.WithProfile("tls"),
		clientmsp.WithCSR(&clientmsp.CSRInfo{
			CN:    host,
			Hosts: []string{host},
		}),
	)
	if err != nil {
		return nil, err
	}
	caInfo, err := m.MSPClient.GetCAInfo()
	if err != nil {
		return nil, err
	}
	si, err := m.MSPClient.GetSigningIdentity(userName)
	if err != nil {
		return nil, err
	}
	pk, err := si.PrivateKey().Bytes()
	if err != nil {
		return nil, err
	}
	caInfoResponse, err := m.MSPClient.GetCAInfo()
	if err != nil {
		return nil, err
	}
	rootCrt := string(caInfoResponse.CAChain)
	privateKey := string(pk)
	certificate := string(si.EnrollmentCertificate())

	codeTarBytes, err := getCodeTarGz(
		address,
		rootCrt,
		privateKey,
		certificate,
		input.Indexes,
	)
	resClient, err := resmgmt.New(m.SDKContext)
	if err != nil {
		return nil, err
	}
	version := "1"
	sequence := 1

	pkg, err := getChaincodePackage(chaincodeName, codeTarBytes)
	if err != nil {
		return nil, err
	}
	packageID := lifecycle.ComputePackageID(chaincodeName, pkg)
	signaturePolicy := input.SignaturePolicy
	sp, err := policydsl.FromString(signaturePolicy)
	if err != nil {
		return nil, err
	}
	committedCCs, err := resClient.LifecycleQueryCommittedCC(m.Channel, resmgmt.LifecycleQueryCommittedCCRequest{Name: chaincodeName})
	if err != nil {
		log.Warnf("Error when getting commited chaincodes: %v", err)
	}
	if len(committedCCs) > 0 {
		version = committedCCs[len(committedCCs)-1].Version
		sequence = int(committedCCs[len(committedCCs)-1].Sequence) + 1
	}
	var collections []*pb.CollectionConfig
	if input.Pdc != "" {
		collections, err = getCollectionConfigFromBytes([]byte(input.Pdc))
		if err != nil {
			return nil, err
		}
	}
	log.Debugf("collections=%v", collections)
	approveCCRequest := resmgmt.LifecycleApproveCCRequest{
		Name:              chaincodeName,
		Version:           version,
		PackageID:         packageID,
		Sequence:          int64(sequence),
		EndorsementPlugin: "escc",
		ValidationPlugin:  "vscc",
		SignaturePolicy:   sp,
		CollectionConfig:  collections,
		InitRequired:      false,
	}
	var wg sync.WaitGroup
	wg.Add(len(m.SDKContextMap))
	for mspID, sdkContext := range m.SDKContextMap {
		mspID := mspID
		sdkContext := sdkContext
		go func() {
			defer wg.Done()
			resClient, err := resmgmt.New(sdkContext)
			if err != nil {
				log.Errorf("Error when creating resmgmt client: %v", err)
				return
			}
			_, err = resClient.LifecycleInstallCC(
				resmgmt.LifecycleInstallCCRequest{
					Label:   input.Name,
					Package: pkg,
				},
				resmgmt.WithTimeout(fab.ResMgmt, 2*time.Minute),
				resmgmt.WithTimeout(fab.PeerResponse, 2*time.Minute),
			)
			if err != nil {
				log.Errorf("Error when installing chaincode: %v", err)
				return
			}
			txID, err := resClient.LifecycleApproveCC(
				m.Channel,
				approveCCRequest,
				resmgmt.WithTargetFilter(&mspFilter{mspID: mspID}),
			)
			if err != nil && !strings.Contains(err.Error(), "redefine uncommitted") {
				log.Errorf("Error when approving chaincode: %v", err)
				return
			}
			log.Infof("%s Chaincode %s approved= %s", mspID, chaincodeName, txID)
		}()
	}
	wg.Wait()
	commitReadiness, err := resClient.LifecycleCheckCCCommitReadiness(m.Channel,
		resmgmt.LifecycleCheckCCCommitReadinessRequest{
			Name:              chaincodeName,
			Version:           version,
			Sequence:          int64(sequence),
			EndorsementPlugin: "escc",
			ValidationPlugin:  "vscc",
			SignaturePolicy:   sp,
			CollectionConfig:  collections,
			InitRequired:      false,
		})
	if err != nil {
		return nil, err
	}
	log.Infof("Chaincode %s readiness= %v", chaincodeName, commitReadiness)
	txID, err := resClient.LifecycleCommitCC(
		m.Channel,
		resmgmt.LifecycleCommitCCRequest{
			Name:              chaincodeName,
			Version:           version,
			Sequence:          int64(sequence),
			EndorsementPlugin: "escc",
			ValidationPlugin:  "vscc",
			SignaturePolicy:   sp,
			CollectionConfig:  collections,
			InitRequired:      false,
		},
		resmgmt.WithTimeout(fab.ResMgmt, 2*time.Minute),
		resmgmt.WithTimeout(fab.PeerResponse, 2*time.Minute),
	)
	if err != nil {
		return nil, err
	}
	log.Infof("Chaincode %s committed= %s", chaincodeName, txID)
	return &models.DeployChaincodeResponse{
		ChannelName:     m.Channel,
		PackageID:       packageID,
		Version:         version,
		Sequence:        sequence,
		ChaincodeName:   chaincodeName,
		PrivateKey:      privateKey,
		Certificate:     certificate,
		RootCertificate: string(caInfo.CAChain),
	}, nil
}

func mapCertificateList(certs []string) ([]*x509.Certificate, error) {
	var x509Certs []*x509.Certificate
	for _, cert := range certs {
		x509Cert, err := ParseX509Certificate([]byte(cert))
		if err != nil {
			return nil, err
		}
		x509Certs = append(x509Certs, x509Cert)
	}
	return x509Certs, nil
}

func ParseX509Certificate(contents []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(contents)
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

func (m mutationResolver) InvokeChaincode(ctx context.Context, input models.InvokeChaincodeInput) (*models.InvokeChaincodeResponse, error) {
	chContext := m.SDK.ChannelContext(
		m.Channel,
		fabsdk.WithOrg(m.Organization),
		fabsdk.WithUser(m.User),
	)
	chClient, err := channel.New(chContext)
	if err != nil {
		return nil, err
	}
	var byteArgs [][]byte
	for _, arg := range input.Args {
		byteArgs = append(byteArgs, []byte(arg))
	}

	transientMap := map[string][]byte{}
	for _, transient := range input.TransientMap {
		transientMap[transient.Key] = []byte(transient.Value)
	}
	execReponse, err := chClient.Execute(
		channel.Request{
			ChaincodeID:     input.ChaincodeName,
			Fcn:             input.Function,
			Args:            byteArgs,
			TransientMap:    transientMap,
			InvocationChain: []*fab.ChaincodeCall{},
			IsInit:          false,
		},
	)
	if err != nil {
		return nil, err
	}
	return &models.InvokeChaincodeResponse{
		Response:        string(execReponse.Payload),
		ChaincodeStatus: int(execReponse.ChaincodeStatus),
		TransactionID:   string(execReponse.TransactionID),
	}, nil
}

type endorsementPolicy struct {
	ChannelConfigPolicy string `json:"channelConfigPolicy,omitempty"`
	SignaturePolicy     string `json:"signaturePolicy,omitempty"`
}

// getCollectionConfig retrieves the collection configuration
// from the supplied byte array; the byte array must contain a
// json-formatted array of collectionConfigJson elements
func getCollectionConfigFromBytes(cconfBytes []byte) ([]*pb.CollectionConfig, error) {
	cconf := &[]collectionConfigJson{}
	err := json.Unmarshal(cconfBytes, cconf)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse the collection configuration")
	}

	ccarray := make([]*pb.CollectionConfig, 0, len(*cconf))
	for _, cconfitem := range *cconf {
		p, err := policydsl.FromString(cconfitem.Policy)
		if err != nil {
			return nil, errors.WithMessagef(err, "invalid policy %s", cconfitem.Policy)
		}

		cpc := &pb.CollectionPolicyConfig{
			Payload: &pb.CollectionPolicyConfig_SignaturePolicy{
				SignaturePolicy: p,
			},
		}

		var ep *pb.ApplicationPolicy
		if cconfitem.EndorsementPolicy != nil {
			signaturePolicy := cconfitem.EndorsementPolicy.SignaturePolicy
			channelConfigPolicy := cconfitem.EndorsementPolicy.ChannelConfigPolicy
			ep, err = getApplicationPolicy(signaturePolicy, channelConfigPolicy)
			if err != nil {
				return nil, errors.WithMessagef(err, "invalid endorsement policy [%#v]", cconfitem.EndorsementPolicy)
			}
		}

		// Set default requiredPeerCount and MaxPeerCount if not specified in json
		requiredPeerCount := int32(0)
		maxPeerCount := int32(1)
		if cconfitem.RequiredPeerCount != nil {
			requiredPeerCount = *cconfitem.RequiredPeerCount
		}
		if cconfitem.MaxPeerCount != nil {
			maxPeerCount = *cconfitem.MaxPeerCount
		}

		cc := &pb.CollectionConfig{
			Payload: &pb.CollectionConfig_StaticCollectionConfig{
				StaticCollectionConfig: &pb.StaticCollectionConfig{
					Name:              cconfitem.Name,
					MemberOrgsPolicy:  cpc,
					RequiredPeerCount: requiredPeerCount,
					MaximumPeerCount:  maxPeerCount,
					BlockToLive:       cconfitem.BlockToLive,
					MemberOnlyRead:    cconfitem.MemberOnlyRead,
					MemberOnlyWrite:   cconfitem.MemberOnlyWrite,
					EndorsementPolicy: ep,
				},
			},
		}

		ccarray = append(ccarray, cc)
	}

	return ccarray, nil
}
func getApplicationPolicy(signaturePolicy, channelConfigPolicy string) (*pb.ApplicationPolicy, error) {
	if signaturePolicy == "" && channelConfigPolicy == "" {
		// no policy, no problem
		return nil, nil
	}

	if signaturePolicy != "" && channelConfigPolicy != "" {
		// mo policies, mo problems
		return nil, errors.New(`cannot specify both "--signature-policy" and "--channel-config-policy"`)
	}

	var applicationPolicy *pb.ApplicationPolicy
	if signaturePolicy != "" {
		signaturePolicyEnvelope, err := policydsl.FromString(signaturePolicy)
		if err != nil {
			return nil, errors.Errorf("invalid signature policy: %s", signaturePolicy)
		}

		applicationPolicy = &pb.ApplicationPolicy{
			Type: &pb.ApplicationPolicy_SignaturePolicy{
				SignaturePolicy: signaturePolicyEnvelope,
			},
		}
	}

	if channelConfigPolicy != "" {
		applicationPolicy = &pb.ApplicationPolicy{
			Type: &pb.ApplicationPolicy_ChannelConfigPolicyReference{
				ChannelConfigPolicyReference: channelConfigPolicy,
			},
		}
	}

	return applicationPolicy, nil
}

type collectionConfigJson struct {
	Name              string             `json:"name"`
	Policy            string             `json:"policy"`
	RequiredPeerCount *int32             `json:"requiredPeerCount"`
	MaxPeerCount      *int32             `json:"maxPeerCount"`
	BlockToLive       uint64             `json:"blockToLive"`
	MemberOnlyRead    bool               `json:"memberOnlyRead"`
	MemberOnlyWrite   bool               `json:"memberOnlyWrite"`
	EndorsementPolicy *endorsementPolicy `json:"endorsementPolicy,omitempty"`
}

func (m mutationResolver) QueryChaincode(ctx context.Context, input models.QueryChaincodeInput) (*models.QueryChaincodeResponse, error) {
	chContext := m.SDK.ChannelContext(
		m.Channel,
		fabsdk.WithOrg(m.Organization),
		fabsdk.WithUser(m.User),
	)
	chClient, err := channel.New(chContext)
	if err != nil {
		return nil, err
	}
	var byteArgs [][]byte
	for _, arg := range input.Args {
		byteArgs = append(byteArgs, []byte(arg))
	}
	transientMap := map[string][]byte{}
	for _, transient := range input.TransientMap {
		transientMap[transient.Key] = []byte(transient.Value)
	}
	execReponse, err := chClient.Query(
		channel.Request{
			ChaincodeID:     input.ChaincodeName,
			Fcn:             input.Function,
			Args:            byteArgs,
			TransientMap:    transientMap,
			InvocationChain: []*fab.ChaincodeCall{},
			IsInit:          false,
		},
	)
	if err != nil {
		return nil, err
	}
	return &models.QueryChaincodeResponse{
		Response:        string(execReponse.Payload),
		ChaincodeStatus: int(execReponse.ChaincodeStatus),
	}, nil
}
