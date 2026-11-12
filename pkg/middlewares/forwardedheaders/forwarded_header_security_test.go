package forwardedheaders

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gorillawebsocket "github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/host"
	"github.com/traefik/traefik/v3/pkg/middlewares/requestdecorator"
	httpmuxer "github.com/traefik/traefik/v3/pkg/muxer/http"
)

// listenAddr is the address bound by the test servers. They always listen on
// loopback; trust is decided by the trustedIPs range passed to the chain, so
// using a TEST-NET range makes the loopback test client effectively untrusted.
const listenAddr = "127.0.0.1:0"

// newSecureChain builds the same handler chain as a Traefik entry point for the
// security tests: X-Forwarded-* handling (with a trusted proxy range), invalid
// host rejection, request host decoration and a Host-based router.
func newSecureChain(t *testing.T, trustedIPs []string, insecure bool, router http.Handler) http.Handler {
	t.Helper()

	decorated, err := requestdecorator.WrapHandler(requestdecorator.New(nil))(router)
	require.NoError(t, err)

	chain, err := NewXForwarded(insecure, trustedIPs, nil, false, false, decorated)
	require.NoError(t, err)

	return denyInvalidHostForTest(chain)
}

// denyInvalidHostForTest mirrors server.denyInvalidHost without importing the
// server package (which would pull the whole entry point machinery).
func denyInvalidHostForTest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Host != "" && !host.IsValid(req.Host) {
			http.Error(rw, "Bad Request", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(rw, req)
	})
}

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	listener, err := net.Listen("tcp", listenAddr)
	require.NoError(t, err)

	server := &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: handler},
	}
	server.Start()
	t.Cleanup(server.Close)

	return server
}

func newHostRouter(t *testing.T) http.Handler {
	t.Helper()

	parser, err := httpmuxer.NewSyntaxParser()
	require.NoError(t, err)

	mux := httpmuxer.NewMuxer(parser, nil)

	backend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("X-Served-Host", req.Host)
		rw.Header().Set("X-Forwarded-Host-Header", req.Header.Get(XForwardedHost))
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok"))
	})

	require.NoError(t, mux.AddRoute("Host(`app.example.com`)", "", 0, "", backend))
	require.NoError(t, mux.AddRoute("Host(`admin.example.com`)", "", 0, "", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("admin"))
	})))

	return mux
}

// TestSecureRoutingBoundary drives a real HTTP server with the entry point
// handler chain, covering direct connections, trusted and untrusted peers, a
// Host/X-Forwarded-Host conflict, normalization and invalid authorities.
func TestSecureRoutingBoundary(t *testing.T) {
	// 203.0.113.0/24 is a TEST-NET-3 range that never contains a real client,
	// so every loopback test connection is treated as untrusted.
	const untrustedRange = "203.0.113.0/24"

	router := newHostRouter(t)
	handler := newSecureChain(t, []string{untrustedRange}, false, router)

	server := newTestServer(t, handler)
	_, serverPort := splitTestAddr(t, server.Listener.Addr().String())

	doRequest := func(t *testing.T, hostHeader, xfh string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		req.Host = hostHeader
		req.RequestURI = ""
		if xfh != "" {
			req.Header.Set(XForwardedHost, xfh)
		}
		resp, err := server.Client().Transport.RoundTrip(req)
		require.NoError(t, err)
		return resp
	}

	testCases := []struct {
		desc           string
		host           string
		xfh            string
		raw            bool
		expectedStatus int
		expectedBody   string
		expectedXFH    string
	}{
		{
			desc:           "direct request matches the Host router",
			host:           "app.example.com",
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
			expectedXFH:    "app.example.com",
		},
		{
			desc:           "direct request with uppercase and port is normalized",
			host:           "APP.EXAMPLE.COM:" + serverPort,
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
			expectedXFH:    "APP.EXAMPLE.COM:" + serverPort,
		},
		{
			desc:           "direct request with trailing dot is normalized",
			host:           "app.example.com.",
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
			expectedXFH:    "app.example.com.",
		},
		{
			desc:           "unknown host does not match any router",
			host:           "unknown.example.org",
			expectedStatus: http.StatusNotFound,
		},
		{
			desc:           "untrusted client cannot steer routing with X-Forwarded-Host",
			host:           "app.example.com",
			xfh:            "admin.example.com",
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
			expectedXFH:    "app.example.com",
		},
		{
			desc:           "untrusted client X-Forwarded-Host is rebuilt from the real Host",
			host:           "app.example.com",
			xfh:            "evil.example.org",
			expectedStatus: http.StatusOK,
			expectedXFH:    "app.example.com",
		},
		{
			desc:           "control character in the Host header is rejected",
			host:           "app.example.com\r.evil",
			raw:            true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			desc:           "malformed port in the Host header is rejected",
			host:           "app.example.com:99999",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			var resp *http.Response
			if test.raw {
				extra := map[string]string{}
				if test.xfh != "" {
					extra[XForwardedHost] = test.xfh
				}
				resp = doRawRequest(t, server.Listener.Addr().String(), test.host, extra)
			} else {
				resp = doRequest(t, test.host, test.xfh)
			}
			defer resp.Body.Close()

			assert.Equal(t, test.expectedStatus, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			if test.expectedBody != "" {
				assert.Equal(t, test.expectedBody, string(body))
			}
			if test.expectedXFH != "" {
				assert.Equal(t, test.expectedXFH, resp.Header.Get("X-Forwarded-Host-Header"))
			}
		})
	}

	t.Run("trusted proxy X-Forwarded-Host is preserved for the backend", func(t *testing.T) {
		// A chain whose trusted range covers the loopback test connection.
		trustedHandler := newSecureChain(t, []string{"127.0.0.0/8"}, false, router)
		trustedServer := newTestServer(t, trustedHandler)

		req, err := http.NewRequest(http.MethodGet, trustedServer.URL, nil)
		require.NoError(t, err)
		req.Host = "app.example.com"
		req.RequestURI = ""
		req.Header.Set(XForwardedHost, "internal.example.com:8443")

		resp, err := trustedServer.Client().Transport.RoundTrip(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "internal.example.com:8443", resp.Header.Get("X-Forwarded-Host-Header"))
	})

	t.Run("trusted proxy invalid X-Forwarded-Host is dropped and rebuilt", func(t *testing.T) {
		trustedHandler := newSecureChain(t, []string{"127.0.0.0/8"}, false, router)
		trustedServer := newTestServer(t, trustedHandler)

		// A syntactically sendable but unroutable value (port out of range):
		// the Go transport accepts it while host.Normalize rejects it.
		req, err := http.NewRequest(http.MethodGet, trustedServer.URL, nil)
		require.NoError(t, err)
		req.Host = "app.example.com"
		req.RequestURI = ""
		req.Header.Set(XForwardedHost, "bad.example.com:99999")

		resp, err := trustedServer.Client().Transport.RoundTrip(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "app.example.com", resp.Header.Get("X-Forwarded-Host-Header"))
	})
}

// TestSecureRoutingBoundaryTLS repeats the boundary checks over HTTPS so that
// the SNI/Host combination cannot be used to bypass the Host router.
func TestSecureRoutingBoundaryTLS(t *testing.T) {
	const untrustedRange = "203.0.113.0/24"

	router := newHostRouter(t)
	handler := newSecureChain(t, []string{untrustedRange}, false, router)

	listener, err := net.Listen("tcp", listenAddr)
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(handler)
	require.NoError(t, server.Listener.Close())
	server.Listener = listener
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	t.Run("valid SNI and Host over TLS", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		req.Host = "app.example.com"
		req.RequestURI = ""

		resp, err := server.Client().Transport.RoundTrip(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("forged X-Forwarded-Host over TLS cannot change the route", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		req.Host = "app.example.com"
		req.RequestURI = ""
		req.Header.Set(XForwardedHost, "admin.example.com")

		resp, err := server.Client().Transport.RoundTrip(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "ok", readBody(t, resp))
		assert.Equal(t, "app.example.com", resp.Header.Get("X-Forwarded-Host-Header"))
	})
}

// TestSecureRoutingWebSocketUpgrade verifies that a websocket upgrade keeps
// using the real Host for routing and never trusts an untrusted X-Forwarded-Host.
func TestSecureRoutingWebSocketUpgrade(t *testing.T) {
	const untrustedRange = "203.0.113.0/24"

	upgrader := gorillawebsocket.Upgrader{}
	wsBackend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(rw, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		mt, message, err := conn.ReadMessage()
		if err != nil {
			return
		}
		_ = conn.WriteMessage(mt, append(message, []byte("-"+req.Header.Get(XForwardedHost))...))
	})

	parser, err := httpmuxer.NewSyntaxParser()
	require.NoError(t, err)
	mux := httpmuxer.NewMuxer(parser, nil)
	require.NoError(t, mux.AddRoute("Host(`ws.example.com`)", "", 0, "", wsBackend))

	handler := newSecureChain(t, []string{untrustedRange}, false, mux)
	server := newTestServer(t, handler)

	wsURL := "ws://" + server.Listener.Addr().String()
	headers := http.Header{}
	headers.Set("Host", "ws.example.com")
	// An untrusted client tries to claim another host: it must be stripped.
	headers.Set(XForwardedHost, "admin.example.com")

	conn, resp, err := gorillawebsocket.DefaultDialer.Dial(wsURL, headers)
	if resp != nil {
		defer resp.Body.Close()
	}
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.WriteMessage(gorillawebsocket.TextMessage, []byte("ping")))

	_, message, err := conn.ReadMessage()
	require.NoError(t, err)
	// The backend must observe the X-Forwarded-Host rebuilt from the real Host,
	// not the value forged by the untrusted client.
	assert.Equal(t, "ping-ws.example.com", string(message))
}

func splitTestAddr(t *testing.T, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	return host, port
}

// doRawRequest sends a handcrafted HTTP/1.1 request over a raw TCP connection,
// which is the only way to deliver header values (control characters, ...) that
// the standard http.Client refuses to write.
func doRawRequest(t *testing.T, addr, hostHeader string, extraHeaders map[string]string) *http.Response {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	var builder strings.Builder
	fmt.Fprintf(&builder, "GET / HTTP/1.1\r\nHost: %s\r\n", hostHeader)
	for k, v := range extraHeaders {
		fmt.Fprintf(&builder, "%s: %s\r\n", k, v)
	}
	builder.WriteString("Connection: close\r\n\r\n")

	_, err = conn.Write([]byte(builder.String()))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}
