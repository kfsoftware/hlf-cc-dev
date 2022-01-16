package serve

import (
	"fmt"
	"github.com/hyperledger/fabric-config/configtx"
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
		mapSdkContext[organization.Name] = sdk.Context(
			fabsdk.WithUser(conf.Fabric.Org),
			fabsdk.WithOrg(organization.Name),
		)
	}
	opts := server.BlockchainServerOpts{
		Address:        c.address,
		MetricsAddress: c.metricsAddress,
		SDK:            sdk,
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
