package filter

import (
	"fmt"
	"strings"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// Config is the parsed filter configuration.
//
// Example (typed_config is a xds.type.v3.TypedStruct):
//
//	allowed_headers: [accept, content-type, x-request-id]
//	response_allowed_headers: [content-type, content-length]
//
// Header names are matched case-insensitively. Pseudo headers (":path",
// ":status", ...) are never removed. A direction whose list is omitted
// (nil) is left untouched; an explicitly empty list removes every
// non-pseudo header.
type Config struct {
	// RequestAllowed is nil when request headers must not be sanitised.
	RequestAllowed map[string]struct{}
	// ResponseAllowed is nil when response headers must not be sanitised.
	ResponseAllowed map[string]struct{}
}

type Parser struct{}

func (Parser) Parse(any *anypb.Any, _ api.ConfigCallbackHandler) (interface{}, error) {
	ts := &xds.TypedStruct{}
	if err := any.UnmarshalTo(ts); err != nil {
		return nil, fmt.Errorf("unmarshal typed struct: %w", err)
	}
	fields := ts.GetValue().GetFields()
	cfg := &Config{}
	var err error
	if cfg.RequestAllowed, err = stringSet(fields, "allowed_headers"); err != nil {
		return nil, err
	}
	if cfg.ResponseAllowed, err = stringSet(fields, "response_allowed_headers"); err != nil {
		return nil, err
	}
	for key := range fields {
		if key != "allowed_headers" && key != "response_allowed_headers" {
			return nil, fmt.Errorf("unknown config field %q", key)
		}
	}
	if cfg.RequestAllowed == nil && cfg.ResponseAllowed == nil {
		return nil, fmt.Errorf("at least one of allowed_headers or response_allowed_headers is required")
	}
	return cfg, nil
}

// Merge lets a more specific (route level) config override the parent one
// per direction.
func (Parser) Merge(parent, child interface{}) interface{} {
	p, c := parent.(*Config), child.(*Config)
	out := *p
	if c.RequestAllowed != nil {
		out.RequestAllowed = c.RequestAllowed
	}
	if c.ResponseAllowed != nil {
		out.ResponseAllowed = c.ResponseAllowed
	}
	return &out
}

// stringSet returns nil when key is absent, otherwise the lower-cased set.
func stringSet(fields map[string]*structpb.Value, key string) (map[string]struct{}, error) {
	v, ok := fields[key]
	if !ok {
		return nil, nil
	}
	list := v.GetListValue()
	if list == nil {
		return nil, fmt.Errorf("%s must be a list of strings", key)
	}
	set := make(map[string]struct{}, len(list.Values))
	for _, item := range list.Values {
		name, ok := item.GetKind().(*structpb.Value_StringValue)
		if !ok || strings.TrimSpace(name.StringValue) == "" {
			return nil, fmt.Errorf("%s must contain only non-empty strings", key)
		}
		set[strings.ToLower(strings.TrimSpace(name.StringValue))] = struct{}{}
	}
	return set, nil
}
