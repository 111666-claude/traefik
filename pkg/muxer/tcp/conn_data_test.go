package tcp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

type connDataAddr struct{ addr string }

func (a connDataAddr) Network() string { return "tcp" }
func (a connDataAddr) String() string  { return a.addr }

func TestNewConnDataServerName(t *testing.T) {
	testCases := []struct {
		desc           string
		serverName     string
		expectedServer string
	}{
		{
			desc:           "simple server name",
			serverName:     "example.com",
			expectedServer: "example.com",
		},
		{
			desc:           "uppercase server name is lowercased",
			serverName:     "EXAMPLE.COM",
			expectedServer: "example.com",
		},
		{
			desc:           "trailing dot is removed",
			serverName:     "example.com.",
			expectedServer: "example.com",
		},
		{
			desc:           "IPv6 literal is normalized",
			serverName:     "2001:DB8::1",
			expectedServer: "2001:db8::1",
		},
		{
			desc:           "empty server name stays empty",
			serverName:     "",
			expectedServer: "",
		},
		{
			desc:           "control character drops the server name",
			serverName:     "evil\r.com",
			expectedServer: "",
		},
		{
			desc:           "malformed authority drops the server name",
			serverName:     "example.com:99999",
			expectedServer: "",
		},
	}

	addr := connDataAddr{addr: "10.0.0.1:1234"}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			connData, err := NewConnData(test.serverName, addr, nil)
			require.NoError(t, err)
			assert.Equal(t, test.expectedServer, connData.serverName)
			assert.Equal(t, "10.0.0.1", connData.remoteIP)
		})
	}
}

func TestNewConnDataInvalidServerNameFallsBackToCatchAll(t *testing.T) {
	muxer, err := NewMuxer(nil)
	require.NoError(t, err)

	handler := func(_ string) tcp.Handler {
		return tcp.HandlerFunc(func(conn tcp.WriteCloser) {
			_, _ = conn.Write([]byte("ok"))
		})
	}

	require.NoError(t, muxer.AddRoute("HostSNI(`app.example.com`)", "", 0, "", handler("named")))
	require.NoError(t, muxer.AddRoute("HostSNI(`*`)", "", 0, "", handler("catchall")))

	connData, err := NewConnData("evil\r.app.example.com", connDataAddr{addr: "10.0.0.1:1234"}, nil)
	require.NoError(t, err)

	matched, isCatchAll := muxer.Match(connData)
	require.NotNil(t, matched)
	assert.True(t, isCatchAll, "an invalid SNI must only reach the HostSNI(`*`) catch-all")
}

// Ensure the fake addr satisfies net.Addr at compile time.
var _ net.Addr = connDataAddr{}
