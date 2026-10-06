package filter

import (
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

type sanitizer struct {
	api.PassThroughStreamFilter
	config *Config
}

func NewFactory(config interface{}, _ api.FilterCallbackHandler) api.StreamFilter {
	return &sanitizer{config: config.(*Config)}
}

func (f *sanitizer) DecodeHeaders(h api.RequestHeaderMap, _ bool) api.StatusType {
	sanitize(h, f.config.RequestAllowed)
	return api.Continue
}

func (f *sanitizer) EncodeHeaders(h api.ResponseHeaderMap, _ bool) api.StatusType {
	sanitize(h, f.config.ResponseAllowed)
	return api.Continue
}

// sanitize removes every header whose name is not in allowed.
// A nil allowed set disables sanitising.
func sanitize(h api.HeaderMap, allowed map[string]struct{}) {
	if allowed == nil {
		return
	}
	var remove []string
	for name := range h.GetAllHeaders() {
		if strings.HasPrefix(name, ":") {
			continue
		}
		if _, ok := allowed[strings.ToLower(name)]; !ok {
			remove = append(remove, name)
		}
	}
	for _, name := range remove {
		h.Del(name)
	}
}
