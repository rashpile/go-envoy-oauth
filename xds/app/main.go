package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var configPath string
	var templatePath string
	var port int
	var listenAddr string

	flag.StringVar(&configPath, "config", "xds/gateway-auth.yaml", "Path to gateway configuration file")
	flag.StringVar(&templatePath, "template", "", "Path to Envoy template configuration file (optional)")
	flag.IntVar(&port, "port", 18000, "XDS server port")
	flag.StringVar(&listenAddr, "listen", "127.0.0.1", "XDS server listen address; the served config contains secrets, keep it on loopback unless Envoy runs on another host")
	flag.Parse()

	// Create XDS server
	server, err := NewXDSServer(configPath, templatePath)
	if err != nil {
		log.Fatalf("Failed to create XDS server: %v", err)
	}

	// Handle shutdown gracefully
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("Shutting down XDS server...")
		server.Stop()
		os.Exit(0)
	}()

	// Start server
	if templatePath != "" {
		log.Printf("Starting XDS server on port %d with config %s and template %s", port, configPath, templatePath)
	} else {
		log.Printf("Starting XDS server on port %d with config %s", port, configPath)
	}
	if err := server.Start(listenAddr, port); err != nil {
		log.Fatalf("Failed to start XDS server: %v", err)
	}
}
