package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

// initCertMagic initializes the CertMagic configuration for the XDS server
func (s *XDSServer) initCertMagic() error {
	config := s.config

	// Skip if SSL is not enabled
	if !config.SSL.Enabled {
		return nil
	}

	// Determine storage path
	storagePath := config.SSL.StoragePath
	if storagePath == "" {
		xdg := os.Getenv("XDG_DATA_HOME")
		if xdg == "" {
			home, _ := os.UserHomeDir()
			xdg = filepath.Join(home, ".local", "share")
		}
		storagePath = filepath.Join(xdg, "certmagic")
	}

	// Create storage directory
	if err := os.MkdirAll(storagePath, 0o755); err != nil {
		return fmt.Errorf("create storage dir: %v", err)
	}

	// Configure CertMagic storage
	certmagic.Default.Storage = &certmagic.FileStorage{Path: storagePath}

	// Set ACME configuration
	if config.SSL.Staging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	} else {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	}
	certmagic.DefaultACME.Email = config.SSL.ACMEEmail
	certmagic.DefaultACME.Agreed = true

	// Force HTTP-01 ONLY (since Envoy owns :443)
	certmagic.DefaultACME.DisableTLSALPNChallenge = true
	certmagic.DefaultACME.DisableHTTPChallenge = false

	s.certManager = certmagic.NewDefault()

	log.Printf("CertMagic initialized with storage: %s", storagePath)
	if config.SSL.Staging {
		log.Printf("Using Let's Encrypt staging environment")
	}

	return nil
}

// collectDomains collects all domains that need TLS certificates
func (s *XDSServer) collectDomains() []string {
	domainMap := make(map[string]bool)

	// Collect domains from clients where tls: true
	for _, client := range s.config.Clients {
		if client.TLS && client.Domain != "" {
			domainMap[client.Domain] = true
		}
	}

	// Convert map to slice
	domains := make([]string, 0, len(domainMap))
	for domain := range domainMap {
		domains = append(domains, domain)
	}

	return domains
}

// startHTTPChallenge starts the HTTP server for ACME challenges
func (s *XDSServer) startHTTPChallenge() error {
	if s.certManager == nil {
		return nil
	}

	// Collect domains from config
	domains := s.collectDomains()
	if len(domains) == 0 {
		log.Printf("No domains configured for TLS certificates")
		return nil
	}

	// Setup HTTP server for ACME challenges FIRST
	mux := http.NewServeMux()
	acme := certmagic.NewACMEIssuer(s.certManager, certmagic.DefaultACME)

	// Handle ACME challenge requests
	mux.Handle("/", acme.HTTPChallengeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only ACME challenge paths are handled, everything else returns 204
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	})))

	// Determine HTTP port for challenges
	httpPort := s.config.SSL.HTTPPort
	if httpPort == 0 {
		httpPort = 8080
	}

	s.httpServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", httpPort),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start HTTP server in background BEFORE managing certificates
	go func() {
		log.Printf("HTTP-01 challenge server listening on port %d", httpPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Give the HTTP server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Now manage certificates (obtain or renew) - this will use the HTTP server for challenges
	log.Printf("Managing certificates for domains: %s", strings.Join(domains, ", "))
	ctx := context.Background()
	if err := s.certManager.ManageSync(ctx, domains); err != nil {
		return fmt.Errorf("manage certs: %v", err)
	}
	log.Printf("Certificates obtained/renewed for: %s", strings.Join(domains, ", "))

	return nil
}

// stopHTTPChallenge gracefully stops the HTTP challenge server
func (s *XDSServer) stopHTTPChallenge() {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down HTTP server: %v", err)
		}
	}
}

// getCertificatePath returns the path to the certificate for a given domain
func (s *XDSServer) getCertificatePath(domain string) (certPath, keyPath string, err error) {
	if s.certManager == nil {
		return "", "", fmt.Errorf("CertMagic not initialized")
	}

	// Get certificate from CertMagic cache
	cert, err := s.certManager.CacheManagedCertificate(context.Background(), domain)
	if err != nil {
		return "", "", fmt.Errorf("failed to get certificate for %s: %w", domain, err)
	}

	// CertMagic stores certificates in memory, but we need file paths for Envoy
	// We'll need to export them to temporary files or use the storage path
	storagePath := s.config.SSL.StoragePath
	if storagePath == "" {
		xdg := os.Getenv("XDG_DATA_HOME")
		if xdg == "" {
			home, _ := os.UserHomeDir()
			xdg = filepath.Join(home, ".local", "share")
		}
		storagePath = filepath.Join(xdg, "certmagic")
	}

	// CertMagic stores certificates in a specific structure
	// certificates/acme-v02.api.letsencrypt.org-directory/domain.com/domain.com.crt
	// certificates/acme-v02.api.letsencrypt.org-directory/domain.com/domain.com.key

	acmeDir := "acme-v02.api.letsencrypt.org-directory"
	if s.config.SSL.Staging {
		acmeDir = "acme-staging-v02.api.letsencrypt.org-directory"
	}

	certPath = filepath.Join(storagePath, "certificates", acmeDir, domain, domain+".crt")
	keyPath = filepath.Join(storagePath, "certificates", acmeDir, domain, domain+".key")

	// Verify files exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("certificate file not found: %s", certPath)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("key file not found: %s", keyPath)
	}

	_ = cert // Use cert to avoid unused variable warning
	return certPath, keyPath, nil
}

// collectDomainsFrom collects domains needing certs from provided config
func collectDomainsFrom(cfg *GatewayConfig) []string {
	m := map[string]struct{}{}
	for _, c := range cfg.Clients {
		if c.TLS && c.Domain != "" {
			m[c.Domain] = struct{}{}
		}
	}
	domains := make([]string, 0, len(m))
	for d := range m {
		domains = append(domains, d)
	}
	return domains
}

// handleSSLConfigChange ensures certificates are obtained for any new domains and reloads SDS
func (s *XDSServer) handleSSLConfigChange(oldCfg, newCfg *GatewayConfig) {
	if s == nil || s.certManager == nil || !newCfg.SSL.Enabled {
		return
	}
	oldDomains := collectDomainsFrom(oldCfg)
	newDomains := collectDomainsFrom(newCfg)

	// find if there are any new domains in newDomains not present in oldDomains
	need := false
	for _, nd := range newDomains {
		found := false
		for _, od := range oldDomains {
			if nd == od {
				found = true
				break
			}
		}
		if !found {
			need = true
			log.Printf("New domain detected that needs certificate: %s", nd)
		}
	}
	if !need || len(newDomains) == 0 {
		return
	}
	log.Printf("Acquiring certificates for domains: %v", newDomains)
	ctx := context.Background()
	if err := s.certManager.ManageSync(ctx, newDomains); err != nil {
		log.Printf("Warning: failed to acquire certificates for new domains: %v", err)
		return
	}
	log.Printf("Successfully acquired/renewed certificates for domains: %v", newDomains)
	if s.sdsServer != nil {
		log.Printf("Reloading certificates into SDS...")
		if err := s.sdsServer.loadCertificates(); err != nil {
			log.Printf("Warning: failed to reload certificates for SDS: %v", err)
		} else {
			log.Printf("Successfully reloaded certificates into SDS")
		}
	}
}
