package redirect

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares/requestdecorator"
)

// TestRedirectSchemeCanonicalHost verifies that the Location header is built
// from the host normalized by the request decorator, so that redirection stays
// consistent with the Host router decision (lower case, no trailing dot,
// no port or IPv6 brackets).
func TestRedirectSchemeCanonicalHost(t *testing.T) {
	testCases := []struct {
		desc        string
		rawHost     string
		expectedURL string
	}{
		{
			desc:        "uppercase host is lowercased in the Location",
			rawHost:     "APP.EXAMPLE.COM",
			expectedURL: "https://app.example.com",
		},
		{
			desc:        "trailing dot is removed in the Location",
			rawHost:     "app.example.com.",
			expectedURL: "https://app.example.com",
		},
		{
			desc:        "port is stripped from the Location",
			rawHost:     "app.example.com:8080",
			expectedURL: "https://app.example.com",
		},
		{
			desc:        "simple host is preserved",
			rawHost:     "app.example.com",
			expectedURL: "https://app.example.com",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
			handler, err := NewRedirectScheme(t.Context(), next, dynamic.RedirectScheme{Scheme: "https"}, "traefikTest")
			require.NoError(t, err)

			decorator := requestdecorator.New(nil)
			wrapped := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				decorator.ServeHTTP(rw, req, handler.ServeHTTP)
			})

			req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			req.Host = test.rawHost
			req.RequestURI = "/path"
			req.URL.Host = ""

			recorder := httptest.NewRecorder()
			wrapped.ServeHTTP(recorder, req)

			require.Equal(t, http.StatusFound, recorder.Code)
			location, err := recorder.Result().Location()
			require.NoError(t, err)
			assert.Equal(t, test.expectedURL+"/path", location.String())
		})
	}
}

// TestRedirectSchemeFallsBackToRawHost verifies that without the request
// decorator in the chain, the redirect middleware still works using the raw
// Host header (standalone usage and backward compatibility).
func TestRedirectSchemeFallsBackToRawHost(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	handler, err := NewRedirectScheme(t.Context(), next, dynamic.RedirectScheme{Scheme: "https"}, "traefikTest")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://foo:8000/path", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusFound, recorder.Code)
	location, err := recorder.Result().Location()
	require.NoError(t, err)
	assert.Equal(t, "https://foo/path", location.String())
}
