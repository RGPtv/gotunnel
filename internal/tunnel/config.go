package tunnel

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// AppConfig is the top-level YAML configuration structure.
// Exactly one of ServerConfig or ClientConfig must be set.
type AppConfig struct {
	ServerConfig *ServerConfig `yaml:"serverConfig"`
	ClientConfig *ClientConfig `yaml:"clientConfig"`
}

// ServerConfig holds all settings for running gotunnel in server mode.
type ServerConfig struct {
	HTTPAddr        string   `yaml:"http"`
	HTTPSAddr       string   `yaml:"https"`
	TunAddr         string   `yaml:"tun"`
	Token           string   `yaml:"token"`
	CertFile        string   `yaml:"cert"`
	KeyFile         string   `yaml:"key"`
	Domain          string   `yaml:"domain"`
	Inspect         string   `yaml:"inspect"`
	InspectUser     string   `yaml:"inspectUser"`
	InspectPass     string   `yaml:"inspectPass"`
	NoTLS           bool     `yaml:"noTLS"`
	PoolSize        int      `yaml:"poolSize"`
	AllowedTCPPorts []string `yaml:"allowedTCPPorts"` // if set, only these remote addrs are allowed for TCP tunnels
}

// ClientConfig holds all settings for running gotunnel in client mode.
type ClientConfig struct {
	Server        string         `yaml:"server"`
	Token         string         `yaml:"token"`
	SkipTLSVerify bool           `yaml:"skipTLSVerify"`
	NoTLS         bool           `yaml:"noTLS"`
	Tunnels       []TunnelConfig `yaml:"tunnels"`
}

// TunnelConfig defines a single tunnel to be opened by the client.
type TunnelConfig struct {
	Name      string `yaml:"name"`
	Target    string `yaml:"target"`
	Type      string `yaml:"type"`
	Subdomain string `yaml:"subdomain"`
	Remote    string `yaml:"remote"`
}

// LoadConfig searches for config.yml then config.yaml in the current working
// directory, parses it, and validates the result. It returns a descriptive
// error if no file is found, parsing fails, or validation fails.
func LoadConfig() (*AppConfig, error) {
	data, filename, err := readConfigFile()
	if err != nil {
		return nil, err
	}

	var cfg AppConfig
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", filename, err)
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// readConfigFile tries config.yml then config.yaml and returns the file
// contents and the name of the file that was found.
func readConfigFile() ([]byte, string, error) {
	candidates := []string{"config.yml", "config.yaml"}
	var missing []string

	for _, name := range candidates {
		data, err := os.ReadFile(name)
		if err == nil {
			return data, name, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			missing = append(missing, "- "+name)
			continue
		}
		// Unexpected error (permissions, etc.)
		return nil, name, fmt.Errorf("could not read %s: %w", name, err)
	}

	return nil, "", fmt.Errorf(
		"no configuration file found.\nExpected:\n%s",
		strings.Join(missing, "\n"),
	)
}

// validateConfig enforces mutual exclusivity and required-field rules.
func validateConfig(cfg *AppConfig) error {
	hasServer := cfg.ServerConfig != nil
	hasClient := cfg.ClientConfig != nil

	if hasServer && hasClient {
		return errors.New(
			"invalid configuration: both 'serverConfig' and 'clientConfig' are present.\n" +
				"Only one root configuration section is allowed at a time.\n" +
				"Remove the section that does not apply to this instance.",
		)
	}
	if !hasServer && !hasClient {
		return errors.New(
			"invalid configuration: neither 'serverConfig' nor 'clientConfig' is present.\n" +
				"Your config.yaml must contain exactly one of these root sections.",
		)
	}

	if hasServer {
		return validateServerConfig(cfg.ServerConfig)
	}
	return validateClientConfig(cfg.ClientConfig)
}

func validateServerConfig(s *ServerConfig) error {
	if s.HTTPSAddr != "" && (s.CertFile == "" || s.KeyFile == "") {
		return errors.New(
			"invalid serverConfig: 'https' requires both 'cert' and 'key' to be set",
		)
	}
	return nil
}

func validateClientConfig(c *ClientConfig) error {
	if c.Server == "" {
		return errors.New("invalid clientConfig: 'server' is required")
	}
	if c.Token == "" {
		return errors.New("invalid clientConfig: 'token' is required")
	}
	if len(c.Tunnels) == 0 {
		return errors.New("invalid clientConfig: at least one tunnel must be defined under 'tunnels'")
	}

	seen := make(map[string]bool)
	for i, t := range c.Tunnels {
		label := fmt.Sprintf("tunnels[%d]", i)
		if t.Name != "" {
			label = fmt.Sprintf("tunnel %q", t.Name)
			if seen[t.Name] {
				return fmt.Errorf("invalid clientConfig: duplicate tunnel name %q", t.Name)
			}
			seen[t.Name] = true
		}

		if t.Target == "" {
			return fmt.Errorf("invalid clientConfig: %s is missing required field 'target'", label)
		}

		tunnelType := strings.ToLower(t.Type)
		if tunnelType == "" {
			tunnelType = "http"
		}
		if tunnelType != "http" && tunnelType != "tcp" {
			return fmt.Errorf("invalid clientConfig: %s has unknown type %q (must be 'http' or 'tcp')", label, t.Type)
		}
		if tunnelType == "tcp" && t.Remote == "" {
			return fmt.Errorf("invalid clientConfig: %s (type 'tcp') requires 'remote' field (e.g. remote: ':22222')", label)
		}
		if tunnelType != "http" && t.Subdomain != "" {
			return fmt.Errorf("invalid clientConfig: %s 'subdomain' can only be used with type 'http'", label)
		}
	}

	return nil
}
