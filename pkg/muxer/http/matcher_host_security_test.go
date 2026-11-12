package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/middlewares/requestdecorator"
)

// TestHostMatcherRejectsInvalidHost verifies the defense-in-depth guard: even
// if an invalid authority reaches the muxer (the entry point normally rejects
// it earlier), the Host matcher must not route on it.
func TestHostMatcherRejectsInvalidHost(t *testing.T) {
	testCases := []struct {
		desc string
		host string
	}{
		{
			desc: "control character",
			host: "app.example.com\r.evil",
		},
		{
			desc: "out-of-range port",
			host: "app.example.com:99999",
		},
		{
			desc: "malformed bracketed IPv6",
			host: "[fe80::1",
		},
	}

	parser, err := NewSyntaxParser()
	require.NoError(t, err)

	mux := NewMuxer(parser, nil)
	require.NoError(t, mux.AddRoute("Host(`app.example.com`)", "", 0, "", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})))

	decorator := requestdecorator.New(nil)

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
			req.Host = test.host

			w := httptest.NewRecorder()
			decorator.ServeHTTP(w, req, mux.ServeHTTP)

			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}

// TestHostMatcherNormalizedEquivalence verifies that syntactically different
// but equivalent authorities all reach the same router.
func TestHostMatcherNormalizedEquivalence(t *testing.T) {
	parser, err := NewSyntaxParser()
	require.NoError(t, err)

	mux := NewMuxer(parser, nil)
	require.NoError(t, mux.AddRoute("Host(`app.example.com`)", "", 0, "", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})))

	decorator := requestdecorator.New(nil)

	hosts := []string{
		"app.example.com",
		"APP.EXAMPLE.COM",
		"app.example.com.",
		"app.example.com:8080",
		"APP.Example.COM:8443",
	}

	for _, hostHeader := range hosts {
		t.Run(hostHeader, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
			req.Host = hostHeader

			w := httptest.NewRecorder()
			decorator.ServeHTTP(w, req, mux.ServeHTTP)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}
