package host

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	testCases := []struct {
		desc     string
		value    string
		expected string
		invalid  bool
	}{
		{
			desc:     "simple hostname",
			value:    "example.com",
			expected: "example.com",
		},
		{
			desc:     "uppercase is lowercased",
			value:    "EXAMPLE.COM",
			expected: "example.com",
		},
		{
			desc:     "mixed case is lowercased",
			value:    "ExAmPle.CoM",
			expected: "example.com",
		},
		{
			desc:     "trailing dot is removed",
			value:    "example.com.",
			expected: "example.com",
		},
		{
			desc:     "surrounding whitespace is trimmed",
			value:    "  example.com  ",
			expected: "example.com",
		},
		{
			desc:     "port is stripped",
			value:    "example.com:8080",
			expected: "example.com",
		},
		{
			desc:     "empty port is accepted",
			value:    "example.com:",
			expected: "example.com",
		},
		{
			desc:     "IPv4 with port",
			value:    "127.0.0.1:8080",
			expected: "127.0.0.1",
		},
		{
			desc:     "bare IPv4",
			value:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			desc:     "bracketed IPv6 with port",
			value:    "[2001:db8::1]:443",
			expected: "2001:db8::1",
		},
		{
			desc:     "bracketed IPv6 without port",
			value:    "[fe80::1]",
			expected: "fe80::1",
		},
		{
			desc:     "bracketed IPv6 with empty port",
			value:    "[fe80::1]:",
			expected: "fe80::1",
		},
		{
			desc:     "IPv6 is lowercased",
			value:    "[2001:DB8::ABCD]:443",
			expected: "2001:db8::abcd",
		},
		{
			desc:     "single label host",
			value:    "localhost",
			expected: "localhost",
		},
		{
			desc:     "underscore labels are accepted",
			value:    "my_service.internal",
			expected: "my_service.internal",
		},
		{
			desc:     "punycode is accepted",
			value:    "xn--9t9h.com",
			expected: "xn--9t9h.com",
		},
		{
			desc:    "empty value",
			value:   "",
			invalid: true,
		},
		{
			desc:    "whitespace only",
			value:   "   ",
			invalid: true,
		},
		{
			desc:    "only a dot",
			value:   ".",
			invalid: true,
		},
		{
			desc:    "control character in hostname",
			value:   "evil\r.com",
			invalid: true,
		},
		{
			desc:    "line feed in hostname",
			value:   "evil\n.com",
			invalid: true,
		},
		{
			desc:    "tab inside hostname",
			value:   "evil\t.com",
			invalid: true,
		},
		{
			desc:    "DEL character",
			value:   "evil\x7f.com",
			invalid: true,
		},
		{
			desc:    "null byte",
			value:   "evil\x00.com",
			invalid: true,
		},
		{
			desc:    "slash is rejected",
			value:   "example.com/path",
			invalid: true,
		},
		{
			desc:    "at sign is rejected",
			value:   "user@example.com",
			invalid: true,
		},
		{
			desc:    "non-numeric port",
			value:   "example.com:abc",
			invalid: true,
		},
		{
			desc:    "port out of range",
			value:   "example.com:70000",
			invalid: true,
		},
		{
			desc:    "negative port",
			value:   "example.com:-1",
			invalid: true,
		},
		{
			desc:     "unbracketed IPv6 literal is accepted",
			value:    "2001:db8::1",
			expected: "2001:db8::1",
		},
		{
			desc:    "malformed bracketed IPv6",
			value:   "[fe80::1",
			invalid: true,
		},
		{
			desc:    "wildcard is not a routable host",
			value:   "*.example.com",
			invalid: true,
		},
		{
			desc:    "empty label",
			value:   "example..com",
			invalid: true,
		},
		{
			desc:    "multiple trailing dots",
			value:   "example.com..",
			invalid: true,
		},
		{
			desc:    "internal whitespace is rejected",
			value:   "exa mple.com",
			invalid: true,
		},
		{
			desc:     "trailing whitespace after an empty port is trimmed",
			value:    "example.com: ",
			expected: "example.com",
		},
		{
			desc:    "label starting with a hyphen",
			value:   "-evil.example.com",
			invalid: true,
		},
		{
			desc:    "label ending with a hyphen",
			value:   "evil-.example.com",
			invalid: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			actual, err := Normalize(test.value)
			if test.invalid {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrInvalidHost))
				assert.Empty(t, actual)
				assert.False(t, IsValid(test.value))
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expected, actual)
			assert.True(t, IsValid(test.value))
		})
	}
}
