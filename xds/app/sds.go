package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/fsnotify/fsnotify"
)

// SDSServer implements the Secret Discovery Service
type SDSServer struct {
	secret.UnimplementedSecretDiscoveryServiceServer
	mainCache       cache.SnapshotCache  // Use the main XDS cache
	version         uint64
	mu              sync.RWMutex
	certificatePath string
	watcher         *fsnotify.Watcher
}

// NewSDSServer creates a new SDS server instance that uses the main XDS cache
func NewSDSServer(certificatePath string, mainCache cache.SnapshotCache) (*SDSServer, error) {
	// Create file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	sds := &SDSServer{
		mainCache:       mainCache,
		certificatePath: certificatePath,
		watcher:         watcher,
	}

	// Initialize secrets from existing certificates
	if err := sds.loadCertificates(); err != nil {
		log.Printf("Warning: failed to load initial certificates: %v", err)
	}

	// Start watching certificate directory
	go sds.watchCertificates()

	return sds, nil
}

// StreamSecrets handles streaming secret discovery requests
func (s *SDSServer) StreamSecrets(stream secret.SecretDiscoveryService_StreamSecretsServer) error {
	// Create a server instance using our cache
	xdsServer := server.NewServer(context.Background(), s.mainCache, nil)
	return xdsServer.StreamSecrets(stream)
}

// FetchSecrets handles unary secret discovery requests
func (s *SDSServer) FetchSecrets(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	// Create a server instance using our cache
	xdsServer := server.NewServer(context.Background(), s.mainCache, nil)
	return xdsServer.FetchSecrets(ctx, req)
}

// DeltaSecrets handles delta secret discovery requests
func (s *SDSServer) DeltaSecrets(stream secret.SecretDiscoveryService_DeltaSecretsServer) error {
	// Create a server instance using our cache
	xdsServer := server.NewServer(context.Background(), s.mainCache, nil)
	return xdsServer.DeltaSecrets(stream)
}

// loadCertificates loads all certificates from the certificate directory
func (s *SDSServer) loadCertificates() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if certificate path exists
	if _, err := os.Stat(s.certificatePath); os.IsNotExist(err) {
		log.Printf("SDS: Certificate path does not exist: %s", s.certificatePath)
		return nil // Not an error, just no certificates yet
	}

	var secrets []types.Resource

	// Look for certificate files in the directory structure
	// Expected structure: certificates/acme-*/domain/domain.crt and domain.key
	certPattern := filepath.Join(s.certificatePath, "certificates", "*", "*", "*.crt")
	certFiles, err := filepath.Glob(certPattern)
	if err != nil {
		return fmt.Errorf("failed to glob certificate files: %w", err)
	}

	for _, certFile := range certFiles {
		// Extract domain from path
		dir := filepath.Dir(certFile)
		domain := filepath.Base(dir)

		// Skip if not a valid domain certificate
		if !strings.HasSuffix(certFile, domain+".crt") {
			continue
		}

		keyFile := filepath.Join(dir, domain+".key")

		// Check if key file exists
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			log.Printf("SDS: Key file not found for %s: %s", domain, keyFile)
			continue
		}

		// Read certificate and key
		certData, err := os.ReadFile(certFile)
		if err != nil {
			log.Printf("SDS: Failed to read certificate %s: %v", certFile, err)
			continue
		}

		keyData, err := os.ReadFile(keyFile)
		if err != nil {
			log.Printf("SDS: Failed to read key %s: %v", keyFile, err)
			continue
		}

		// Create secret name
		secretName := fmt.Sprintf("server_cert_%s", strings.ReplaceAll(domain, ".", "_"))

		// Create TLS certificate secret
		secret := &tls.Secret{
			Name: secretName,
			Type: &tls.Secret_TlsCertificate{
				TlsCertificate: &tls.TlsCertificate{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{
							InlineBytes: certData,
						},
					},
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{
							InlineBytes: keyData,
						},
					},
				},
			},
		}

		secrets = append(secrets, secret)
		log.Printf("SDS: Loaded certificate for domain %s as secret %s", domain, secretName)
	}

	// Also create a default secret for the first certificate if available
	if len(secrets) > 0 {
		// Add a default secret that points to the first certificate
		firstSecret := secrets[0].(*tls.Secret)
		defaultSecret := &tls.Secret{
			Name: "default_server_cert",
			Type: firstSecret.Type,
		}
		secrets = append(secrets, defaultSecret)
		log.Printf("SDS: Created default_server_cert secret")
	}

	// Update snapshot even if no secrets (to clear old ones)
	return s.updateSnapshot(secrets)
}

// updateSnapshot updates the main XDS cache with secrets
func (s *SDSServer) updateSnapshot(secrets []types.Resource) error {
	// Get the current snapshot from the main cache
	ctx := context.Background()
	currentSnapshot, err := s.mainCache.GetSnapshot(nodeID)
	if err != nil {
		// If no snapshot exists yet, we'll create a new one with just secrets
		atomic.AddUint64(&s.version, 1)
		version := fmt.Sprintf("v%d", s.version)

		snapshot, err := cache.NewSnapshot(
			version,
			map[resource.Type][]types.Resource{
				resource.SecretType: secrets,
			},
		)
		if err != nil {
			return fmt.Errorf("failed to create secret snapshot: %w", err)
		}

		if err := s.mainCache.SetSnapshot(ctx, nodeID, snapshot); err != nil {
			return fmt.Errorf("failed to set secret snapshot: %w", err)
		}

		log.Printf("SDS: Created new snapshot with %d secrets", len(secrets))
		return nil
	}

	// Update the existing snapshot with new secrets
	atomic.AddUint64(&s.version, 1)
	version := fmt.Sprintf("v%d", s.version)

	// Create a new snapshot with updated secrets but keeping other resources
	resources := map[resource.Type][]types.Resource{
		resource.SecretType: secrets,
	}

	// Copy existing resources from current snapshot
	for _, resType := range []resource.Type{resource.ListenerType, resource.RouteType, resource.ClusterType, resource.EndpointType} {
		resMap := currentSnapshot.GetResources(resType)
		if len(resMap) > 0 {
			resList := make([]types.Resource, 0, len(resMap))
			for _, res := range resMap {
				resList = append(resList, res)
			}
			resources[resType] = resList
		}
	}

	snapshot, err := cache.NewSnapshot(version, resources)
	if err != nil {
		return fmt.Errorf("failed to create combined snapshot: %w", err)
	}

	if err := s.mainCache.SetSnapshot(ctx, nodeID, snapshot); err != nil {
		return fmt.Errorf("failed to update snapshot with secrets: %w", err)
	}

	log.Printf("SDS: Updated main snapshot to version %s with %d secrets", version, len(secrets))
	return nil
}

// watchCertificates watches for changes in the certificate directory
func (s *SDSServer) watchCertificates() {
	// Set up directory watchers
	dirs := []string{
		s.certificatePath,
		filepath.Join(s.certificatePath, "certificates"),
	}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); err == nil {
			if err := s.watcher.Add(dir); err != nil {
				log.Printf("SDS: Failed to watch directory %s: %v", dir, err)
			} else {
				log.Printf("SDS: Watching directory %s for certificate changes", dir)
			}
		}
	}

	// Also watch subdirectories
	certDir := filepath.Join(s.certificatePath, "certificates")
	if entries, err := os.ReadDir(certDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				subDir := filepath.Join(certDir, entry.Name())
				if err := s.watcher.Add(subDir); err == nil {
					log.Printf("SDS: Watching directory %s", subDir)

					// Watch domain directories within ACME directories
					if subEntries, err := os.ReadDir(subDir); err == nil {
						for _, subEntry := range subEntries {
							if subEntry.IsDir() {
								domainDir := filepath.Join(subDir, subEntry.Name())
								if err := s.watcher.Add(domainDir); err == nil {
									log.Printf("SDS: Watching domain directory %s", domainDir)
								}
							}
						}
					}
				}
			}
		}
	}

	// Debounce timer to avoid multiple reloads
	var debounceTimer *time.Timer
	var mu sync.Mutex

	reload := func() {
		mu.Lock()
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		debounceTimer = time.AfterFunc(500*time.Millisecond, func() {
			log.Printf("SDS: Certificate change detected, reloading...")
			if err := s.loadCertificates(); err != nil {
				log.Printf("SDS: Failed to reload certificates: %v", err)
			}
		})
		mu.Unlock()
	}

	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			// Check if the event is for a certificate or key file
			if strings.HasSuffix(event.Name, ".crt") || strings.HasSuffix(event.Name, ".key") {
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
					log.Printf("SDS: Certificate file changed: %s", event.Name)
					reload()
				}
			}
			// Also watch for new directories being created
			if event.Op&fsnotify.Create == fsnotify.Create {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					s.watcher.Add(event.Name)
					log.Printf("SDS: Now watching new directory: %s", event.Name)
					reload()
				}
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("SDS: Watcher error: %v", err)
		}
	}
}

// Stop stops the SDS server and cleans up resources
func (s *SDSServer) Stop() {
	if s.watcher != nil {
		s.watcher.Close()
	}
}

// GetSecretName returns the SDS secret name for a given domain
func GetSecretName(domain string) string {
	if domain == "" {
		return "default_server_cert"
	}
	return fmt.Sprintf("server_cert_%s", strings.ReplaceAll(domain, ".", "_"))
}