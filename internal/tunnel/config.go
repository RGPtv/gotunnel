package tunnel

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type ServerConfig struct {
	HTTPAddr    string `json:"http,omitempty"`
	TunAddr     string `json:"tun,omitempty"`
	Token       string `json:"token,omitempty"`
	CertFile    string `json:"cert,omitempty"`
	KeyFile     string `json:"key,omitempty"`
	Auth        string `json:"auth,omitempty"`
	Domain      string `json:"domain,omitempty"`
	NoTLS       bool   `json:"notls,omitempty"`
	HTTPSAddr   string `json:"https,omitempty"`
	Inspect     string `json:"inspect,omitempty"`
	InspectUser string `json:"inspectUser,omitempty"`
	InspectPass string `json:"inspectPass,omitempty"`
	PoolSize    int    `json:"poolSize,omitempty"`
}

type ClientConfig struct {
	Server  string            `json:"server,omitempty"`
	Token   string            `json:"token,omitempty"`
	Tunnels map[string]Tunnel `json:"tunnels,omitempty"`
}

type Config struct {
	Server       string            `json:"server,omitempty"`
	Token        string            `json:"token,omitempty"`
	ServerConfig *ServerConfig     `json:"serverConfig,omitempty"`
	ClientConfig *ClientConfig     `json:"clientConfig,omitempty"`
	Tunnels      map[string]Tunnel `json:"tunnels,omitempty"`
}

type Tunnel struct {
	Target    string `json:"target,omitempty"`
	Type      string `json:"type,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
	Remote    string `json:"remote,omitempty"`
	APIKey    string `json:"apikey,omitempty"`
	Workers   int    `json:"workers,omitempty"`
	Insecure  bool   `json:"insecure,omitempty"`
	NoTLS     bool   `json:"notls,omitempty"`
}

func loadConfig() *Config {
	data, err := os.ReadFile("config.json")
	if err != nil {
		return nil
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("ERROR parsing config.json: %v", err)
	}
	return &cfg
}

func RunStart(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: gotunnel start <tunnel_name>")
		os.Exit(1)
	}
	tunnelName := args[0]

	cfg := loadConfig()
	if cfg == nil {
		log.Fatal("ERROR: config.json not found in current directory")
	}

	// Support both top-level client configuration and "clientConfig" wrapper
	var tunnels map[string]Tunnel
	var globalServer, globalToken string

	if cfg.ClientConfig != nil {
		tunnels = cfg.ClientConfig.Tunnels
		globalServer = cfg.ClientConfig.Server
		globalToken = cfg.ClientConfig.Token
	}

	// Fallback to top-level if not found in ClientConfig
	if len(tunnels) == 0 {
		tunnels = cfg.Tunnels
	}
	if globalServer == "" {
		globalServer = cfg.Server
	}
	if globalToken == "" {
		globalToken = cfg.Token
	}

	t, ok := tunnels[tunnelName]
	if !ok {
		log.Fatalf("ERROR: tunnel '%s' not found in config.json", tunnelName)
	}

	// Reconstruct args to pass to runClient
	clientArgs := []string{}
	if globalServer != "" {
		clientArgs = append(clientArgs, "-server", globalServer)
	}
	if globalToken != "" {
		clientArgs = append(clientArgs, "-token", globalToken)
	}
	if t.Target != "" {
		clientArgs = append(clientArgs, "-target", t.Target)
	}
	if t.Type != "" {
		clientArgs = append(clientArgs, "-type", t.Type)
	}
	if t.Subdomain != "" {
		clientArgs = append(clientArgs, "-subdomain", t.Subdomain)
	}
	if t.Remote != "" {
		clientArgs = append(clientArgs, "-remote", t.Remote)
	}
	if t.APIKey != "" {
		clientArgs = append(clientArgs, "-apikey", t.APIKey)
	}
	if t.Workers > 0 {
		clientArgs = append(clientArgs, "-workers", fmt.Sprintf("%d", t.Workers))
	}
	if t.Insecure {
		clientArgs = append(clientArgs, "-k")
	}
	if t.NoTLS {
		clientArgs = append(clientArgs, "-notls")
	}
	if len(args) > 1 {
		clientArgs = append(clientArgs, args[1:]...)
	}

	RunClient(clientArgs)
}
