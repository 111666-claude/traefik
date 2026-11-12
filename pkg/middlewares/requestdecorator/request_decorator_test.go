package requestdecorator

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/traefik/traefik/v3/pkg/testhelpers"
	"github.com/traefik/traefik/v3/pkg/types"
)

func TestRequestHost(t *testing.T) {
	testCases := []struct {
		desc        string
		url         string
		rawHost     string
		expected    string
		expectValid bool
	}{
		{
			desc:        "host without port",
			url:         "http://host",
			expected:    "host",
			expectValid: true,
		},
		{
			desc:        "host with empty port",
			url:         "http://host:",
			expected:    "host",
			expectValid: true,
		},
		{
			desc:        "IP host with port",
			url:         "http://127.0.0.1:123",
			expected:    "127.0.0.1",
			expectValid: true,
		},
		{
			desc:        "IP host with empty port",
			url:         "http://127.0.0.1:",
			expected:    "127.0.0.1",
			expectValid: true,
		},
		{
			desc:        "uppercase is normalized",
			url:         "http://EXAMPLE.COM",
			expected:    "example.com",
			expectValid: true,
		},
		{
			desc:        "trailing dot is removed",
			url:         "http://example.com.",
			expected:    "example.com",
			expectValid: true,
		},
		{
			desc:        "bracketed IPv6 with port",
			url:         "http://[fe80::1]:123",
			expected:    "fe80::1",
			expectValid: true,
		},
		{
			desc:        "control character makes the host invalid",
			url:         "http://example.com",
			rawHost:     "evil\r.com",
			expected:    "",
			expectValid: false,
		},
		{
			desc:        "malformed authority makes the host invalid",
			url:         "http://example.com",
			rawHost:     "example.com:notaport",
			expected:    "",
			expectValid: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.expected, GetCanonicalHost(r.Context()))
				assert.Equal(t, test.expectValid, IsHostValid(r.Context()))
			})

			rh := New(nil)

			req := testhelpers.MustNewRequest(http.MethodGet, test.url, nil)
			if test.rawHost != "" {
				req.Host = test.rawHost
			}

			rh.ServeHTTP(nil, req, next)
		})
	}
}

func TestRequestFlattening(t *testing.T) {
	testCases := []struct {
		desc     string
		url      string
		expected string
	}{
		{
			desc:     "host with flattening",
			url:      "http://www.github.com",
			expected: "github.com",
		},
		{
			desc:     "host without flattening",
			url:      "http://github.com",
			expected: "github.com",
		},
		{
			desc:     "ip without flattening",
			url:      "http://127.0.0.1",
			expected: "127.0.0.1",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				host := GetCNAMEFlatten(r.Context())
				assert.Equal(t, test.expected, host)
			})

			rh := New(
				&types.HostResolverConfig{
					CnameFlattening: true,
					ResolvConfig:    "/etc/resolv.conf",
					ResolvDepth:     5,
				},
			)

			req := testhelpers.MustNewRequest(http.MethodGet, test.url, nil)

			rh.ServeHTTP(nil, req, next)
		})
	}
}
