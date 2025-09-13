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
	var port int

	flag.StringVar(&configPath, "config", "xds/gateway-auth.yaml", "Path to gateway configuration file")
	flag.IntVar(&port, "port", 18000, "XDS server port")
	flag.Parse()

	// Create XDS server
	server, err := NewXDSServer(configPath)
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
	log.Printf("Starting XDS server on port %d with config %s", port, configPath)
	if err := server.Start(port); err != nil {
		log.Fatalf("Failed to start XDS server: %v", err)
	}
}