package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
)

const (
	nodeID = "envoy-node"
)

type XDSServer struct {
	config       *GatewayConfig
	configPath   string
	templatePath string
	template     *EnvoyTemplate
	cache        cache.SnapshotCache
	version      uint64
	grpcServer   *grpc.Server
}

func NewXDSServer(configPath, templatePath string) (*XDSServer, error) {
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Load template if provided
	var template *EnvoyTemplate
	if templatePath != "" {
		template, err = LoadTemplate(templatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load template: %w", err)
		}
		if template != nil {
			log.Printf("Loaded template from %s", templatePath)
		}
	} else if config.Template != "" {
		template, err = LoadTemplate(config.Template)
		if err != nil {
			return nil, fmt.Errorf("failed to load template from config: %w", err)
		}
		if template != nil {
			log.Printf("Loaded template from %s", config.Template)
		}
	}

	// Create cache (use nil for logger to use default)
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, nil)

	return &XDSServer{
		config:       config,
		configPath:   configPath,
		templatePath: templatePath,
		template:     template,
		cache:        snapshotCache,
		version:      0,
	}, nil
}

func (s *XDSServer) updateSnapshot() error {
	// Reload config
	config, err := LoadConfig(s.configPath)
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}
	s.config = config

	// Reload template if path is specified
	templatePath := s.templatePath
	if templatePath == "" && config.Template != "" {
		templatePath = config.Template
	}
	if templatePath != "" {
		template, err := LoadTemplate(templatePath)
		if err != nil {
			log.Printf("Warning: failed to reload template: %v", err)
		} else {
			s.template = template
		}
	}

	// Generate resources
	listeners, err := MakeListener(s.config)
	if err != nil {
		return fmt.Errorf("failed to create listeners: %w", err)
	}

	routes, err := MakeRoutes(s.config)
	if err != nil {
		return fmt.Errorf("failed to create routes: %w", err)
	}

	clusters, err := MakeClusters(s.config)
	if err != nil {
		return fmt.Errorf("failed to create clusters: %w", err)
	}

	endpoints, err := MakeEndpoints(s.config)
	if err != nil {
		return fmt.Errorf("failed to create endpoints: %w", err)
	}

	// Apply template if available
	var resources map[resource.Type][]types.Resource
	if s.template != nil {
		resources, err = ApplyTemplate(s.template, listeners, routes, clusters, endpoints)
		if err != nil {
			return fmt.Errorf("failed to apply template: %w", err)
		}
	} else {
		resources = map[resource.Type][]types.Resource{
			resource.EndpointType: endpoints,
			resource.ClusterType:  clusters,
			resource.RouteType:    routes,
			resource.ListenerType: listeners,
		}
	}

	// Create snapshot
	version := fmt.Sprintf("v%d", atomic.AddUint64(&s.version, 1))
	snapshot, err := cache.NewSnapshot(version, resources)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	// Update cache
	if err := s.cache.SetSnapshot(context.Background(), nodeID, snapshot); err != nil {
		return fmt.Errorf("failed to set snapshot: %w", err)
	}

	log.Printf("Updated snapshot to version %s", version)
	return nil
}

func (s *XDSServer) watchConfig() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(s.configPath); err != nil {
		return fmt.Errorf("failed to watch config file: %w", err)
	}

	log.Printf("Watching config file: %s", s.configPath)

	// Also watch template file if specified
	templatePath := s.templatePath
	if templatePath == "" && s.config.Template != "" {
		templatePath = s.config.Template
	}
	if templatePath != "" {
		if err := watcher.Add(templatePath); err != nil {
			log.Printf("Warning: failed to watch template file %s: %v", templatePath, err)
		} else {
			log.Printf("Watching template file: %s", templatePath)
		}
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Printf("Config file modified, reloading...")
				// Add a small delay to ensure file write is complete
				time.Sleep(100 * time.Millisecond)
				if err := s.updateSnapshot(); err != nil {
					log.Printf("Failed to update snapshot: %v", err)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func (s *XDSServer) Start(port int) error {
	// Create initial snapshot
	if err := s.updateSnapshot(); err != nil {
		return fmt.Errorf("failed to create initial snapshot: %w", err)
	}

	// Start config watcher in background
	go func() {
		if err := s.watchConfig(); err != nil {
			log.Printf("Config watcher error: %v", err)
		}
	}()

	// Create gRPC server
	s.grpcServer = grpc.NewServer(
		grpc.MaxConcurrentStreams(1000),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 5 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	// Create xDS server
	xdsServer := server.NewServer(context.Background(), s.cache, nil)

	// Register services
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(s.grpcServer, xdsServer)
	endpointservice.RegisterEndpointDiscoveryServiceServer(s.grpcServer, xdsServer)
	clusterservice.RegisterClusterDiscoveryServiceServer(s.grpcServer, xdsServer)
	routeservice.RegisterRouteDiscoveryServiceServer(s.grpcServer, xdsServer)
	listenerservice.RegisterListenerDiscoveryServiceServer(s.grpcServer, xdsServer)

	// Start listening
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	log.Printf("XDS server listening on port %d", port)
	return s.grpcServer.Serve(listener)
}

func (s *XDSServer) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}