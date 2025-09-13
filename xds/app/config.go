package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type GatewayConfig struct {
	Plugin  PluginConfig  `yaml:"plugin"`
	OAuth   OAuthConfig   `yaml:"oauth"`
	Clients []ClientConfig `yaml:"clients"`
}

type PluginConfig struct {
	LibraryPath string `yaml:"library_path"`
}

type OAuthConfig struct {
	IssuerURL     string   `yaml:"issuer_url"`
	ClientID      string   `yaml:"client_id"`
	ClientSecret  string   `yaml:"client_secret"`
	RedirectURL   string   `yaml:"redirect_url"`
	Scopes        []string `yaml:"scopes,omitempty"`
}

type ClientConfig struct {
	ID           string   `yaml:"id"`
	Address      string   `yaml:"address"`
	Port         uint32   `yaml:"port"`
	SSL          bool     `yaml:"ssl"`
	Exclude      bool     `yaml:"exclude"`
	Prefix       string   `yaml:"prefix"`
	ExcludePaths []string `yaml:"exclude_paths,omitempty"`
}

func LoadConfig(path string) (*GatewayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config GatewayConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if config.OAuth.RedirectURL == "" {
		config.OAuth.RedirectURL = "/oauth/callback"
	}

	if config.OAuth.Scopes == nil {
		config.OAuth.Scopes = []string{"openid", "profile", "email"}
	}

	for i := range config.Clients {
		if config.Clients[i].Port == 0 {
			config.Clients[i].Port = 8080
		}
		if config.Clients[i].Prefix == "" {
			config.Clients[i].Prefix = "/"
		}
	}

	// Validate required fields
	if config.Plugin.LibraryPath == "" {
		return nil, fmt.Errorf("plugin.library_path is required")
	}
	if config.OAuth.IssuerURL == "" {
		return nil, fmt.Errorf("oauth.issuer_url is required")
	}
	if config.OAuth.ClientID == "" {
		return nil, fmt.Errorf("oauth.client_id is required")
	}

	for _, client := range config.Clients {
		if client.ID == "" {
			return nil, fmt.Errorf("client.id is required")
		}
		if client.Address == "" {
			return nil, fmt.Errorf("client.address is required for client %s", client.ID)
		}
	}

	return &config, nil
}