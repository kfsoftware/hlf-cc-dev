package serve

import (
	"crypto/x509"
	"fmt"
	"github.com/hyperledger/fabric-config/configtx"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	clientmsp "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/pkg/msp"
	"github.com/kfsoftware/hlf-cc-dev/server"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"strings"
	"time"
)

const (
	serveDesc = `
'serve' command starts the server to provision new tenants for Arise`
	serveExample = `  hlf-cc serve --address="0.0.0.0:8080" --config=./config.yaml`
)

type serveCmd struct {
	address        string
	config         string
	metricsAddress string
}

type serveConfig struct {
	Fabric struct {
		Connection  string `json:"connection"`
		Channel     string `json:"channel"`
		Org         string `json:"org"`
		User        string `json:"user"`
		ChaincodeCA string `json:"chaincodeCA"`
	}
}

func (c serveConfig) validate() error {
	return nil
}

func NewServeCmd() *cobra.Command {
	s := &serveCmd{}
	cmd := &cobra.Command{
		Use:     "serve",
		Short:   "Starts the server",
		Long:    serveDesc,
		Example: serveExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := s.validate(); err != nil {
				return err
			}
			viper.SetConfigFile(s.config)
			err := viper.ReadInConfig()
			if err != nil {
				return err
			}
			conf := &serveConfig{}
			err = viper.Unmarshal(conf)
			if err != nil {
				return err
			}
			return s.run(conf)
		},
	}

	f := cmd.Flags()
	f.StringVar(&s.address, "address", "", "address for the server")
	f.StringVar(&s.metricsAddress, "metrics-address", "", "address for the metrics server")
	f.StringVarP(&s.config, "config", "c", "", "config to start the server")
	return cmd
}

func (c *serveCmd) validate() error {
	if c.address == "" {
		return errors.New("--address is required for the server")
	}
	if c.metricsAddress == "" {
		return errors.New("--metrics-address is required for the server")
	}
	if c.config == "" {
		return errors.New("--config is required")
	}
	return nil
}
func getGatewayParams(serve *serveConfig, sdk *fabsdk.FabricSDK) (*GatewayParams, error) {
	configBackend1, err := sdk.Config()
	if err != nil {
		return nil, err
	}
	adminCertPem, _ := configBackend1.Lookup(fmt.Sprintf("organizations.%s.users.admin.cert.pem", serve.Fabric.Org))
	adminCertKey, _ := configBackend1.Lookup(fmt.Sprintf("organizations.%s.users.admin.key.pem", serve.Fabric.Org))
	peersInt, _ := configBackend1.Lookup(fmt.Sprintf("organizations.%s.peers", serve.Fabric.Org))
	peersArrayInterface := peersInt.([]interface{})
	var peers []string
	idx := 0
	var peerUrl string
	var peerTLSCACert []byte
	for _, item := range peersArrayInterface {
		peerName := item.(string)
		peers = append(peers, peerName)
		peerUrlKey := fmt.Sprintf("peers.%s.url", peerName)
		peerTLSCACertKey := fmt.Sprintf("peers.%s.tlsCACerts.pem", peerName)
		peerUrlInt, _ := configBackend1.Lookup(peerUrlKey)
		peerTLSCACertInt, _ := configBackend1.Lookup(peerTLSCACertKey)
		peerUrl = strings.Replace(peerUrlInt.(string), "grpcs://", "", -1)
		peerTLSCACert = []byte(peerTLSCACertInt.(string))
		idx++
		if idx >= 1 {
			break
		}
	}
	return &GatewayParams{
		adminKey:      adminCertKey.(string),
		adminCert:     adminCertPem.(string),
		peerUrl:       peerUrl,
		peerTLSCACert: peerTLSCACert,
		mspID:         serve.Fabric.Org,
	}, nil
}
func (c *serveCmd) run(conf *serveConfig) error {
	err := conf.validate()
	if err != nil {
		return err
	}
	configBackend := config.FromFile(conf.Fabric.Connection)
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return err
	}
	sdkContext := sdk.Context(
		fabsdk.WithUser(conf.Fabric.User),
		fabsdk.WithOrg(conf.Fabric.Org),
	)

	embeddedBackend, err := configBackend()
	if err != nil {
		return err
	}
	identityCtx, err := msp.ConfigFromBackend(embeddedBackend...)
	if err != nil {
		return err
	}
	caID := conf.Fabric.ChaincodeCA
	caConfig, ok := identityCtx.CAConfig(caID)
	if !ok {
		return fmt.Errorf("CA not found: %s", caID)
	}
	mspClient, err := clientmsp.New(
		sdkContext,
		clientmsp.WithCAInstance(caID),
		clientmsp.WithOrg(conf.Fabric.Org),
	)
	if err != nil {
		return err
	}
	registrarEnrollID, registrarEnrollSecret := caConfig.Registrar.EnrollID, caConfig.Registrar.EnrollSecret
	err = mspClient.Enroll(registrarEnrollID, clientmsp.WithSecret(registrarEnrollSecret))
	if err != nil {
		return err
	}
	resClient, err := resmgmt.New(sdkContext)
	if err != nil {
		return err
	}
	block, err := resClient.QueryConfigBlockFromOrderer(conf.Fabric.Channel)
	if err != nil {
		return err
	}
	cfgBlock, err := resource.ExtractConfigFromBlock(block)
	if err != nil {
		return err
	}
	cftxGen := configtx.New(cfgBlock)
	appConf, err := cftxGen.Application().Configuration()
	if err != nil {
		return err
	}
	mapSdkContext := map[string]context.ClientProvider{}
	for _, organization := range appConf.Organizations {
		sdk, err := fabsdk.New(configBackend)
		if err != nil {
			return err
		}
		mapSdkContext[organization.Name] = sdk.Context(
			fabsdk.WithUser(conf.Fabric.User),
			fabsdk.WithOrg(organization.MSP.Name),
		)
	}
	gwParams, err := getGatewayParams(conf, sdk)
	if err != nil {
		return err
	}
	clientConnection, err := newGrpcConnection(
		gwParams.peerUrl,
		gwParams.peerTLSCACert,
	)
	if err != nil {
		return err
	}
	gwClient, err := getGateway(*gwParams, clientConnection)
	if err != nil {
		return err
	}
	opts := server.BlockchainServerOpts{
		Address:        c.address,
		MetricsAddress: c.metricsAddress,
		SDK:            sdk,
		GWClient:       gwClient,
		SDKContext:     sdkContext,
		SDKContextMap:  mapSdkContext,
		Channel:        conf.Fabric.Channel,
		MSPClient:      mspClient,
		CAConfig:       caConfig,
		Organization:   conf.Fabric.Org,
		User:           conf.Fabric.User,
	}
	s := server.NewServer(opts)
	s.Run()
	return nil
}

type GatewayParams struct {
	adminKey      string
	adminCert     string
	peerUrl       string
	peerTLSCACert []byte
	mspID         string
}

func newIdentity(certificatePEM []byte) (*identity.X509Identity, error) {
	cert, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		return nil, err
	}
	id, err := identity.NewX509Identity("MEDIIOCHAINMSP", cert)
	if err != nil {
		return nil, err
	}
	return id, nil
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign(privateKeyPEM []byte) (identity.Sign, error) {
	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, err
	}

	return sign, nil
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection(peerEndpoint string, tlsCert []byte) (*grpc.ClientConn, error) {
	certificate, err := identity.CertificateFromPEM(tlsCert)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain commit status: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, "")

	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate transaction: %w", err)
	}

	return connection, nil
}
func getGateway(params GatewayParams, clientConnection *grpc.ClientConn) (*client.Gateway, error) {

	id, err := newIdentity([]byte(params.adminCert))
	if err != nil {
		return nil, err
	}
	sign, err := newSign([]byte(params.adminKey))
	if err != nil {
		return nil, err
	}
	// Create a Gateway connection for a specific client identity
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		return nil, err
	}
	return gw, nil
}
