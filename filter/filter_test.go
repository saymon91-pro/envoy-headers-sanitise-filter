package filter

import (
	"testing"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type fakeHeaders struct {
	api.HeaderMap
	m map[string][]string
}

func (f *fakeHeaders) GetAllHeaders() map[string][]string { return f.m }
func (f *fakeHeaders) Del(k string)                       { delete(f.m, k) }

func TestSanitize(t *testing.T) {
	h := &fakeHeaders{m: map[string][]string{
		":path": {"/"}, "Accept": {"x"}, "X-Evil": {"1"}, "cookie": {"a"},
	}}
	sanitize(h, map[string]struct{}{"accept": {}})
	if len(h.m) != 2 || h.m["Accept"] == nil || h.m[":path"] == nil {
		t.Fatalf("unexpected headers: %v", h.m)
	}
}

func TestSanitizeNilAllowedIsNoop(t *testing.T) {
	h := &fakeHeaders{m: map[string][]string{"x": {"1"}}}
	sanitize(h, nil)
	if len(h.m) != 1 {
		t.Fatal("headers removed")
	}
}

func parse(t *testing.T, v map[string]any) (interface{}, error) {
	s, err := structpb.NewStruct(v)
	if err != nil {
		t.Fatal(err)
	}
	a, err := anypb.New(&xds.TypedStruct{Value: s})
	if err != nil {
		t.Fatal(err)
	}
	return Parser{}.Parse(a, nil)
}

func TestParse(t *testing.T) {
	c, err := parse(t, map[string]any{"allowed_headers": []any{"Accept", " X-Id "}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := c.(*Config)
	if _, ok := cfg.RequestAllowed["x-id"]; !ok || len(cfg.RequestAllowed) != 2 || cfg.ResponseAllowed != nil {
		t.Fatalf("bad config: %+v", cfg)
	}
	for _, bad := range []map[string]any{
		{}, {"allowed_headers": "x"}, {"allowed_headers": []any{""}}, {"allowed_headers": []any{}, "typo": 1},
	} {
		if _, err := parse(t, bad); err == nil {
			t.Fatalf("expected error for %v", bad)
		}
	}
}

func TestMerge(t *testing.T) {
	p := &Config{RequestAllowed: map[string]struct{}{"a": {}}, ResponseAllowed: map[string]struct{}{"b": {}}}
	c := &Config{RequestAllowed: map[string]struct{}{"c": {}}}
	m := Parser{}.Merge(p, c).(*Config)
	if _, ok := m.RequestAllowed["c"]; !ok {
		t.Fatal("child not applied")
	}
	if _, ok := m.ResponseAllowed["b"]; !ok {
		t.Fatal("parent lost")
	}
}
