package generate_certs

import (
	"context"
	"github.com/hashicorp/yamux"
	"github.com/kfsoftware/hlf-cc-dev/gql/models"
	"github.com/kfsoftware/hlf-cc-dev/log"
	"github.com/kfsoftware/getout/pkg/tunnel"
	"github.com/pkg/errors"
	"github.com/shurcooL/graphql"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io/ioutil"
	"k8s.io/client-go/util/homedir"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type Paths struct {
	base string
	tmp  string
}

func mustGetHLFCCPaths() Paths {
	base := filepath.Join(homedir.HomeDir(), ".hlf-cc")
	if fromEnv := os.Getenv("HLF_CC_ROOT"); fromEnv != "" {
		base = fromEnv
		log.Infof("using environment override HLF_CC_ROOT=%s", fromEnv)
	}
	base, err := filepath.Abs(base)
	if err != nil {
		panic(errors.Wrap(err, "cannot get absolute path"))
	}
	return Paths{base: base, tmp: os.TempDir()}
}

func (p Paths) CertsDir(chaincode string) string {
	return filepath.Join(p.base, "certs", chaincode)
}

const (
	startDesc    = ``
	startExample = ``
)

type startCmd struct {
	tenant                int
	chaincode             string
	localChaincodeAddress string
	tunnelAddress         string
	apiUrl                string
	pdcFile               string
	accessToken           string
	metaInf               string
	chaincodeAddress      string
}

func (c startCmd) validate() error {
	if c.tenant == 0 {
		return errors.New("--tenant is required")
	}
	if c.chaincodeAddress == "" {
		return errors.New("--chaincode is required")
	}
	if c.chaincode == "" {
		return errors.New("--chaincode is required")
	}
	if c.tunnelAddress == "" {
		return errors.New("--tunnelAddress is required")
	}
	if c.localChaincodeAddress == "" {
		return errors.New("--localChaincodeAddress is required")
	}
	if c.apiUrl == "" {
		return errors.New("--apiUrl is required")
	}
	if c.metaInf != "" {
		if _, err := os.Stat(c.metaInf); os.IsNotExist(err) {
			return err
		}
	}

	return nil
}
func ensureDirs(paths ...string) error {
	for _, p := range paths {
		log.Infof("Ensure creating dir: %q", p)
		if err := os.MkdirAll(p, 0755); err != nil {
			return errors.Wrapf(err, "failed to ensure create directory %q", p)
		}
	}
	return nil
}
func (c startCmd) run() error {
	var err error
	p := mustGetHLFCCPaths()
	err = ensureDirs(
		p.CertsDir(c.chaincode),
	)
	if err != nil {
		return err
	}

	gqlClient := graphql.NewClient(c.apiUrl, nil)
	ctx := context.Background()
	input := models.DeployChaincodeInput{
		Name:             c.chaincode,
		TenantID:         c.tenant,
		ChaincodeAddress: c.chaincodeAddress,
	}
	var m struct {
		DeployChaincode struct {
			ChaincodeName   string `graphql:"chaincodeName"`
			PackageID       string `graphql:"packageID"`
			Version         string `graphql:"version"`
			Sequence        int    `graphql:"sequence"`
			PrivateKey      string `graphql:"privateKey"`
			Certificate     string `graphql:"certificate"`
			RootCertificate string `graphql:"rootCertificate"`
		} `graphql:"deployChaincode(input: $input)"`
	}
	vars := map[string]interface{}{
		"input": input,
	}
	err = gqlClient.Mutate(ctx, &m, vars)
	if err != nil {
		return err
	}
	chaincodeKeyPath := filepath.Join(p.CertsDir(c.chaincode), "chaincode.key")
	err = ioutil.WriteFile(chaincodeKeyPath, []byte(m.DeployChaincode.PrivateKey), 0777)
	if err != nil {
		return err
	}
	chaincodeCertPath := filepath.Join(p.CertsDir(c.chaincode), "chaincode.pem")
	err = ioutil.WriteFile(chaincodeCertPath, []byte(m.DeployChaincode.Certificate), 0777)
	if err != nil {
		return err
	}
	caCertPath := filepath.Join(p.CertsDir(c.chaincode), "ca.pem")
	err = ioutil.WriteFile(caCertPath, []byte(m.DeployChaincode.RootCertificate), 0777)
	if err != nil {
		return err
	}
	sni, _, err := net.SplitHostPort(c.chaincodeAddress)
	if err != nil {
		return err
	}
	err = startTunnel(
		c.tunnelAddress,
		c.localChaincodeAddress,
		sni,
	)
	if err != nil {
		return err
	}
	return err
}
func startTunnel(tunnelAddr string, localAddress string, sni string) error {
	conn, err := net.Dial("tcp", tunnelAddr)
	if err != nil {
		panic(err)
	}
	session, err := yamux.Client(conn, nil)
	if err != nil {
		panic(err)
	}
	tunnelCli := tunnel.NewTunnelClient(
		session,
		localAddress,
	)
	err = tunnelCli.StartTlsTunnel(sni)
	if err != nil {
		return err
	}
	err = tunnelCli.Start()
	if err != nil {
		return err
	}
	return nil
}

func NewStartCmd() *cobra.Command {
	c := &startCmd{}
	cmd := &cobra.Command{
		Use:     "start",
		Short:   "Start development for chaincode",
		Long:    startDesc,
		Example: startExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			viper.AutomaticEnv()
			err = viper.BindEnv("")
			if err != nil {
				return nil
			}
			viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.chaincodeAddress, "chaincodeAddress", "", "chaincode address to be accessed by the peer(needs to be publicly accessible)")
	f.IntVar(&c.tenant, "tenant", 0, "tenant id")
	f.StringVar(&c.chaincode, "chaincode", "", "chaincode name within the channel")
	f.StringVar(&c.localChaincodeAddress, "localChaincode", "", "address of the local chaincode server, example: localhost:9999")
	f.StringVar(&c.apiUrl, "apiUrl", "", "apiUrl to interact with the peers")
	f.StringVar(&c.pdcFile, "pdc", "", "pdc file json, see examples/pdc.json")
	f.StringVar(&c.tunnelAddress, "tunnelAddress", "", "address of the local chaincode server, example: localhost:9999")
	f.StringVar(&c.accessToken, "accessToken", "", "access token")
	f.StringVar(&c.metaInf, "metaInf", "", "metadata")
	return cmd
}
