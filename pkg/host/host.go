// Package host centralizes the validation and normalization of host values
// used at the routing boundary: the HTTP Host header, the TLS SNI server name
// and the X-Forwarded-Host header.
//
// Every value participating in a routing decision goes through Normalize so
// that case, a trailing dot, an optional port and IPv6 bracket notation can no
// longer be used to make two syntactically different values address the same
// router, and invalid values containing control characters or malformed
// authorities are rejected before they reach the muxer.
package host

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// ErrInvalidHost is returned when a host value cannot be safely used for
// routing: it contains control characters or whitespace inside the authority,
// its port or bracketed IPv6 notation is malformed, or it does not contain any
// routable label.
var ErrInvalidHost = errors.New("invalid host")

// Normalize validates and canonicalizes an authority (the value of an HTTP
// Host header, an SNI server name or an X-Forwarded-Host header value).
//
// It lowercases the value, removes surrounding whitespace and a single
// trailing dot, strips a valid port (re-bracketing an IPv6 address when one is
// present), and rejects control characters and malformed authorities. The
// returned host never contains a port or brackets.
func Normalize(value string) (string, error) {
	if value == "" {
		return "", ErrInvalidHost
	}

	if containsControlCharacter(value) {
		return "", ErrInvalidHost
	}

	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", ErrInvalidHost
	}

	hostname := trimmed

	// A bare IPv6 literal (without brackets or port), as it may appear in an
	// SNI server name, is a valid routable host on its own.
	if ip := net.ParseIP(hostname); ip != nil {
		return strings.ToLower(hostname), nil
	}

	// A bracketed address is an IPv6 authority, optionally carrying a port.
	if strings.HasPrefix(trimmed, "[") {
		if without, ok := strings.CutSuffix(trimmed, "]"); ok {
			hostname = strings.TrimPrefix(without, "[")
		} else if h, port, err := net.SplitHostPort(trimmed); err == nil {
			if err := validatePort(port); err != nil {
				return "", err
			}
			hostname = h
		} else {
			return "", ErrInvalidHost
		}

		if net.ParseIP(hostname) == nil {
			return "", ErrInvalidHost
		}
		return strings.ToLower(hostname), nil
	}

	// A single colon separates a hostname or IPv4 address from its port.
	if strings.Count(trimmed, ":") == 1 {
		h, port, _ := strings.Cut(trimmed, ":")
		if err := validatePort(port); err != nil {
			return "", err
		}
		hostname = h
	}

	// An unbracketed value containing several colons but not parsing as an IP
	// is a malformed IPv6 authority, and internal whitespace never is valid.
	if strings.ContainsAny(hostname, " \t") {
		return "", ErrInvalidHost
	}
	if strings.Contains(hostname, ":") && net.ParseIP(hostname) == nil {
		return "", ErrInvalidHost
	}
	if net.ParseIP(hostname) != nil {
		return strings.ToLower(hostname), nil
	}

	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	if hostname == "" || !isValidHostname(hostname) {
		return "", ErrInvalidHost
	}

	return hostname, nil
}

// IsValid reports whether value normalizes without an error.
func IsValid(value string) bool {
	_, err := Normalize(value)
	return err == nil
}

// validatePort rejects out-of-range and non-numeric ports. An empty port (the
// "host:" form) is accepted: the standard library parses it and no port
// participates in routing.
func validatePort(port string) error {
	if port == "" {
		return nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return ErrInvalidHost
	}
	return nil
}

// isValidHostname validates a hostname without a port. The allowed character
// set matches the one historically accepted by the Host/HostSNI matchers:
// alphanumeric labels, digits, hyphens and underscores, separated by dots.
// Underscores are kept on purpose because internal service names rely on them.
func isValidHostname(hostname string) bool {
	if len(hostname) > 253 || strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}

	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return false
		}
	}

	return true
}

func containsControlCharacter(value string) bool {
	for i := range len(value) {
		if value[i] < 0x20 || value[i] == 0x7f {
			return true
		}
	}
	return false
}
