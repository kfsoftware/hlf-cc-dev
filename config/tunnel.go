package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/shibukawa/configdir"
)

type TunnelConfigItem struct {
	SNI             string
	ForwardTo       string
	ExternalAddress string
}
type TunnelConfig struct {
}

var (
	configDirs = configdir.New("kfs", "hlf-cc-dev")
)

func NewTunnelConfig() (*TunnelConfig, error) {
	return &TunnelConfig{}, nil
}
func (c *TunnelConfig) Get(host string) (*TunnelConfigItem, error) {
	s256 := sha256.New()
	s256.Write([]byte(host))
	hash := s256.Sum(nil)
	hashHex := fmt.Sprintf("%x", hash)
	filePath := fmt.Sprintf("tunnels/%s", hashHex)
	folders := configDirs.QueryFolders(configdir.Global)
	contentBytes, err := folders[0].ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	item := &TunnelConfigItem{}
	err = json.Unmarshal(contentBytes, &item)
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (c *TunnelConfig) Add(tunnelKey string, cfg TunnelConfigItem) (*TunnelConfig, error) {
	s256 := sha256.New()
	s256.Write([]byte(tunnelKey))
	hash := s256.Sum(nil)
	hashHex := fmt.Sprintf("%x", hash)
	filePath := fmt.Sprintf("tunnels/%s", hashHex)
	folders := configDirs.QueryFolders(configdir.Global)
	jsonBytes, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	err = folders[0].WriteFile(filePath, jsonBytes)
	if err != nil {
		return nil, err
	}

	return c, nil
}
