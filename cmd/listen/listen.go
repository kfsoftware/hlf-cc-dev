package listen

import (
	"fmt"
	"github.com/kfsoftware/getout/pkg/tunnel"
	"github.com/kfsoftware/hlf-cc-dev/config"
	"github.com/kfsoftware/hlf-cc-dev/log"
	"github.com/lithammer/shortuuid/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"net"
	"strings"
	"time"
)

type listenCmd struct {
	forwardTo       string
	tunnelAddress   string
	tunnelSubdomain string
}

const (
	listenDesc    = ""
	listenExample = ""
)

func (c listenCmd) validate() error {
	return nil
}

func (c listenCmd) run() error {
	var sni string
	tunnelAddress := c.tunnelAddress
	tunnelConfig, err := config.NewTunnelConfig()
	if err != nil {
		return err
	}
	tunnelKey := fmt.Sprintf("%s_%s", c.forwardTo, c.tunnelAddress)
	log.Debugf("tunnelKey: %s", tunnelKey)
	cfgItem, err := tunnelConfig.Get(tunnelKey)
	if err != nil {
		hostname := strings.ToLower(shortuuid.New()[:10])
		sni = fmt.Sprintf("%s.%s", hostname, c.tunnelSubdomain)
		_, err = tunnelConfig.Add(tunnelKey, config.TunnelConfigItem{
			ForwardTo: c.forwardTo,
			SNI:       sni,
		})
		if err != nil {
			return err
		}
	} else {
		sni = cfgItem.SNI
	}
	sniReal, _, err := net.SplitHostPort(sni)
	if err != nil {
		return err
	}
	log.Infof("Forwarding %s to %s", sni, tunnelAddress)
	for {
		err := startTunnel(
			tunnelAddress,
			c.forwardTo,
			sniReal,
		)
		if err != nil {
			log.Errorf("Error starting the tunnel: %s", err)
			log.Infof("Retrying in 5 seconds...")
			time.Sleep(5 * time.Second)
		} else {
			log.Infof("Tunnel closed")
			break
		}
	}
	return nil
}

func startTunnel(tunnelAddr string, localAddress string, sni string) error {
	tunnelCli := tunnel.NewTunnelClient(
		tunnelAddr,
	)
	err := tunnelCli.StartTlsTunnel(sni, localAddress)
	if err != nil {
		return err
	}
	return nil
}

func NewListenCmd() *cobra.Command {
	c := &listenCmd{}
	cmd := &cobra.Command{
		Use:     "listen",
		Short:   "Listen for incoming connections",
		Long:    listenDesc,
		Example: listenExample,
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
	f.StringVar(&c.tunnelAddress, "tunnel-addr", "", "Tunnel address to connect to")
	f.StringVar(&c.forwardTo, "forward-to", "", "address of the local chaincode server, example: localhost:9999")
	f.StringVar(&c.tunnelSubdomain, "tunnel-subdomain", "", "subdomain of the tunnel, example: cc.kfs.es")
	return cmd
}
