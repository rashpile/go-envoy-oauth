package main

import (
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	"github.com/rashpile/go-envoy-oauth/filter"
)

const Name = "gateway-auth"

func init() {
	http.RegisterHttpFilterFactoryAndConfigParser(Name, filter.FilterFactory, &filter.Parser{})
}

func main() {}
