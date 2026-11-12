package requestdecorator

import (
	"context"
	"net/http"

	"github.com/containous/alice"
	"github.com/traefik/traefik/v3/pkg/host"
	"github.com/traefik/traefik/v3/pkg/types"
)

const (
	canonicalKey key = "canonical"
	flattenKey   key = "flatten"
	validKey     key = "valid"
)

type key string

// RequestDecorator is the struct for the middleware that normalizes the request
// Host (lower case, no trailing dot, port or IPv6 brackets) and stores it in the
// request context for later use by the Host matchers.
type RequestDecorator struct {
	hostResolver *Resolver
}

// New creates a new request host middleware.
func New(hostResolverConfig *types.HostResolverConfig) *RequestDecorator {
	requestDecorator := &RequestDecorator{}
	if hostResolverConfig != nil {
		requestDecorator.hostResolver = &Resolver{
			CnameFlattening: hostResolverConfig.CnameFlattening,
			ResolvConfig:    hostResolverConfig.ResolvConfig,
			ResolvDepth:     hostResolverConfig.ResolvDepth,
		}
	}
	return requestDecorator
}

func (r *RequestDecorator) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	normalized, err := host.Normalize(req.Host)

	ctx := context.WithValue(req.Context(), canonicalKey, normalized)
	ctx = context.WithValue(ctx, validKey, err == nil)
	reqt := req.WithContext(ctx)

	if r.hostResolver != nil && r.hostResolver.CnameFlattening && err == nil {
		flatHost := r.hostResolver.CNAMEFlatten(reqt.Context(), normalized)
		reqt = reqt.WithContext(context.WithValue(reqt.Context(), flattenKey, flatHost))
	}

	next(rw, reqt)
}

// GetCanonicalHost retrieves the canonical host from the given context (previously stored in the request context by the middleware).
func GetCanonicalHost(ctx context.Context) string {
	if val, ok := ctx.Value(canonicalKey).(string); ok {
		return val
	}

	return ""
}

// IsHostValid reports whether the request Host header normalized successfully.
// A false value means the authority contains control characters or is otherwise
// malformed, so the request must not be routed on its host.
func IsHostValid(ctx context.Context) bool {
	if val, ok := ctx.Value(validKey).(bool); ok {
		return val
	}

	return false
}

// GetCNAMEFlatten return the flat name if it is present in the context.
func GetCNAMEFlatten(ctx context.Context) string {
	if val, ok := ctx.Value(flattenKey).(string); ok {
		return val
	}

	return ""
}

// WrapHandler Wraps a ServeHTTP with next to an alice.Constructor.
func WrapHandler(handler *RequestDecorator) alice.Constructor {
	return func(next http.Handler) (http.Handler, error) {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			handler.ServeHTTP(rw, req, next.ServeHTTP)
		}), nil
	}
}
