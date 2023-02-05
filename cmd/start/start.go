package start

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/kfsoftware/hlf-cc-dev/config"
	"github.com/kfsoftware/hlf-cc-dev/gql/models"
	"github.com/kfsoftware/hlf-cc-dev/log"
	"github.com/pkg/errors"
	"github.com/shurcooL/graphql"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/client-go/util/homedir"
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
	chaincode             string
	localChaincodeAddress string
	apiUrl                string
	pdcFile               string
	accessToken           string
	metaInf               string
	signaturePolicy       string
	envFile               string
	tunnelAddress         string
	channel               string
}

func (c startCmd) validate() error {
	if c.tunnelAddress == "" {
		return errors.New("--tunnelAddress is required")
	}
	if c.signaturePolicy == "" {
		return errors.New("--signaturePolicy is required")
	}
	if c.chaincode == "" {
		return errors.New("--chaincode is required")
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

func parseECDSAPrivateKey(contents []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(contents)
	var ecdsaKey *ecdsa.PrivateKey
	var err error
	ecdsaKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return ecdsaKey, nil
}
func (c startCmd) run() error {
	var err error
	p := mustGetHLFCCPaths()
	err = ensureDirs(
		p.CertsDir(c.chaincode),
	)
	if err != nil {
		log.Errorf("failed to ensure directories: %v", err)
		return errors.Wrapf(err, "failed to ensure dirs")
	}
	gqlClient := graphql.NewClient(c.apiUrl, nil)
	ctx := context.Background()
	tunnelConfig, err := config.NewTunnelConfig()
	if err != nil {
		return errors.Wrap(err, "failed to create tunnel config")
	}
	tunnelKey := fmt.Sprintf("%s_%s", c.localChaincodeAddress, c.tunnelAddress)
	log.Debugf("tunnelKey: %s", tunnelKey)
	tunnelCFGItem, err := tunnelConfig.Get(tunnelKey)
	if err != nil {
		return errors.Wrapf(err, `failed to get tunnel config, run the following command
hlf-cc-dev listen --forward-to=%s --tunnelAddress="xxx:8082"
`, c.localChaincodeAddress)
	}

	chaincodeAddress := tunnelCFGItem.SNI
	pdcContents := ""
	if c.pdcFile != "" {
		pdcContentsBytes, err := ioutil.ReadFile(c.pdcFile)
		if err != nil {
			return errors.Wrapf(err, "failed to read pdc file %q", c.pdcFile)
		}
		pdcContents = string(pdcContentsBytes)
	}
	var indices []*models.CouchDBIndex
	var pdcIndices []*models.CouchDBIndexPdc
	if c.metaInf != "" {
		src := c.metaInf
		// walk through 3 file in the folder
		err = filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
			// must provide real name
			// (see https://golang.org/src/archive/tar/common.go?#L626)
			relname, err := filepath.Rel(src, file)
			if err != nil {
				return err
			}
			if relname == "." {
				return nil
			}
			if (strings.Contains(relname, "statedb/couchdb/indexes") || strings.Contains(relname, "statedb/couchdb/collections")) && !fi.IsDir() {
				contentBytes, err := ioutil.ReadFile(file)
				if err != nil {
					return err
				}
				index := &models.CouchDBIndex{
					ID:       path.Base(relname),
					Contents: string(contentBytes),
				}
				indices = append(indices, index)
				log.Infof("found index file: %s - %s", relname, path.Base(relname))
			}
			if strings.Contains(relname, "statedb/couchdb/collections") && !fi.IsDir() {
				contentBytes, err := ioutil.ReadFile(file)
				if err != nil {
					return err
				}
				pdcName := path.Base(path.Join(relname, "../../"))
				index := &models.CouchDBIndexPdc{
					ID:       path.Base(relname),
					PdcName:  pdcName,
					Contents: string(contentBytes),
				}
				pdcIndices = append(pdcIndices, index)
				log.Infof("found index for PDC %s file: %s - %s", pdcName, relname, path.Base(relname))
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	log.Infof("found %d indexes %v", len(indices), indices)
	log.Infof("found %d pdc indexes %v", len(pdcIndices), pdcIndices)
	input := models.DeployChaincodeInput{
		Channel:          &c.channel,
		Name:             c.chaincode,
		ChaincodeAddress: chaincodeAddress,
		Pdc:              pdcContents,
		SignaturePolicy:  c.signaturePolicy,
		Indexes:          indices,
		PdcIndexes:       pdcIndices,
	}
	var m struct {
		DeployChaincode struct {
			ChaincodeName   string `graphql:"chaincodeName"`
			ChannelName     string `graphql:"channelName"`
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
	pk, err := parseECDSAPrivateKey([]byte(m.DeployChaincode.PrivateKey))
	if err != nil {
		return err
	}
	pkBytes, err := EncodePrivateKey(pk)
	if err != nil {
		return err
	}
	chaincodeKeyPath := filepath.Join(p.CertsDir(c.chaincode), "chaincode.key")
	err = ioutil.WriteFile(chaincodeKeyPath, pkBytes, 0777)
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

	chaincodeKeyB64Path := filepath.Join(p.CertsDir(c.chaincode), "chaincode_b64.key")
	err = ioutil.WriteFile(chaincodeKeyB64Path, []byte(base64.StdEncoding.EncodeToString(pkBytes)), 0777)
	if err != nil {
		return err
	}
	chaincodeCertB64Path := filepath.Join(p.CertsDir(c.chaincode), "chaincode_b64.pem")
	err = ioutil.WriteFile(chaincodeCertB64Path, []byte(base64.StdEncoding.EncodeToString([]byte(m.DeployChaincode.Certificate))), 0777)
	if err != nil {
		return err
	}
	dotEnvFile := fmt.Sprintf(`
CORE_CHAINCODE_ID=%s
CORE_CHAINCODE_ID_NAME=%s
CORE_CHAINCODE_ADDRESS=%s
CORE_CHAINCODE_TLS_KEY_FILE=%s
CORE_CHAINCODE_TLS_CERT_FILE=%s
CORE_CHAINCODE_TLS_CLIENT_CACERT_FILE=%s
CHAINCODE_TLS_DISABLED=false
CORE_PEER_TLS_ROOTCERT_FILE=%s
CORE_TLS_CLIENT_KEY_FILE=%s
CORE_TLS_CLIENT_CERT_FILE=%s
`,
		m.DeployChaincode.PackageID,
		m.DeployChaincode.PackageID,
		c.localChaincodeAddress,
		chaincodeKeyPath,
		chaincodeCertPath,
		caCertPath,
		caCertPath,
		chaincodeKeyB64Path,
		chaincodeCertB64Path,
	)
	dotEnvPath := filepath.Join(p.CertsDir(c.chaincode), ".env")
	err = ioutil.WriteFile(dotEnvPath, []byte(dotEnvFile), 0777)
	if err != nil {
		return err
	}
	if c.envFile != "" {
		err = ioutil.WriteFile(c.envFile, []byte(dotEnvFile), 0777)
		if err != nil {
			return err
		}
	}
	log.Infof("Channel: %s Chaincode: %s", m.DeployChaincode.ChaincodeName, m.DeployChaincode.ChannelName)
	return err
}
func EncodePrivateKey(key interface{}) ([]byte, error) {
	signEncodedPK, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemPk := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: signEncodedPK,
	})
	return pemPk, nil
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
	f.StringVar(&c.chaincode, "chaincode", "", "chaincode name within the channel")
	f.StringVar(&c.localChaincodeAddress, "localChaincode", "", "address of the local chaincode server, example: localhost:9999")
	f.StringVar(&c.tunnelAddress, "tunnelAddress", "", "remote tunnel address, example: localhost:9999")
	f.StringVar(&c.apiUrl, "apiUrl", "", "apiUrl to interact with the peers")
	f.StringVar(&c.pdcFile, "pdc", "", "pdc file json, see examples/pdc.json")
	f.StringVar(&c.accessToken, "accessToken", "", "access token")
	f.StringVar(&c.metaInf, "metaInf", "", "metadata")
	f.StringVar(&c.signaturePolicy, "signaturePolicy", "", "Signature policy")
	f.StringVar(&c.envFile, "env-file", "", "Env file to write the environments")
	f.StringVar(&c.channel, "channel", "", "Channel name")
	return cmd
}
