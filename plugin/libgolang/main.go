package main

import (
	"fmt"
	"os"

	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	"github.com/rashpile/go-envoy-oauth/plugin/filter"
	"github.com/rashpile/go-envoy-oauth/plugin/metrics"
)

const Name = "gateway-auth"

func init() {
	// Initialize metrics FIRST (before filter registration)
	// Logs error but doesn't panic - filter should still work without metrics
	if err := metrics.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway-auth] failed to initialize metrics: %v\n", err)
	}

	// Existing filter registration
	http.RegisterHttpFilterFactoryAndConfigParser(Name, filter.FilterFactory, &filter.Parser{})
}

func main() {}
