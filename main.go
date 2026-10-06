// Envoy golang HTTP filter that removes all headers not on a configured allow list.
// Build with: go build -buildmode=c-shared -o sanitise.so .
package main

import (
	envoyhttp "github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"

	"github.com/saymon91-pro/envoy-headers-sanitise-filter/filter"
)

const filterName = "headers-sanitise"

func init() {
	envoyhttp.RegisterHttpFilterFactoryAndConfigParser(filterName, filter.NewFactory, filter.Parser{})
}

func main() {}

