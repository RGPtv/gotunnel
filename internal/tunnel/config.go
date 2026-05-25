package tunnel

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type Config struct {
	Server  string            `json:"server"`
	Token   string            `json:"token"`
	Tunnels map[string]Tunnel `json:"tunnels"`
}

type Tunnel struct {
	Target    string `json:"target"`
	Type      string `json:"type"`
	Subdomain string `json:"subdomain"`
	Remote    string `json:"remote"`
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

	t, ok := cfg.Tunnels[tunnelName]
	if !ok {
		log.Fatalf("ERROR: tunnel '%s' not found in config.json", tunnelName)
	}

	// Reconstruct args to pass to runClient
	clientArgs := []string{}
	if cfg.Server != "" {
		clientArgs = append(clientArgs, "-server", cfg.Server)
	}
	if cfg.Token != "" {
		clientArgs = append(clientArgs, "-token", cfg.Token)
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
	if len(args) > 1 {
		clientArgs = append(clientArgs, args[1:]...)
	}

	RunClient(clientArgs)
}
