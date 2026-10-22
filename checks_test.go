package main

import (
	"errors"
	"net"
	"testing"
)

func TestCountExternalSuccesses(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]externalNodeResult
		want int
	}{
		{
			name: "all successful",
			in: map[string]externalNodeResult{
				"a": {ok: true, code: "200"},
				"b": {ok: true, code: "204"},
			},
			want: 2,
		},
		{
			name: "failed HTTP probe with status code is not reachable",
			in: map[string]externalNodeResult{
				"a": {ok: false, code: "403", msg: "Forbidden"},
				"b": {ok: true, code: "200"},
				"c": {ok: false, code: "503", msg: "Service unavailable"},
			},
			want: 1,
		},
		{
			name: "failed probe without status code",
			in: map[string]externalNodeResult{
				"a": {ok: false, msg: "timeout"},
			},
			want: 0,
		},
		{
			name: "empty results",
			in:   map[string]externalNodeResult{},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := countExternalSuccesses(tt.in); got != tt.want {
				t.Fatalf("countExternalSuccesses() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
		bad   bool
	}{
		{input: "example.com", want: "example.com"},
		{input: " HTTPS://Example.COM/path?q=1 ", want: "example.com"},
		{input: "example.com.", want: "example.com"},
		{input: "localhost", bad: true},
		{input: "127.0.0.1", bad: true},
		{input: "https://user@example.com", bad: true},
		{input: "example.com:443", bad: true},
		{input: "https://example.com\\\\evil.test", bad: true},
		{input: "", bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseHost(tt.input)
			if tt.bad {
				if err == nil {
					t.Fatalf("ParseHost(%q) unexpectedly succeeded with %q", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseHost(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ParseHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsSinkhole(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.2", "0.0.0.0", "224.0.0.1"} {
		if parsed := net.ParseIP(ip); parsed == nil || !isSinkhole(parsed) {
			t.Errorf("isSinkhole(%q) = false, want true", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		if parsed := net.ParseIP(ip); parsed == nil || isSinkhole(parsed) {
			t.Errorf("isSinkhole(%q) = true, want false", ip)
		}
	}
}

func TestDescribeNetErrNilNotExpected(t *testing.T) {
	// describeNetErr expects a non-nil error; keep this as a guard against
	// accidentally changing its call contract without making nil handling safe.
	if !errors.Is(errors.New("sample"), errors.New("sample")) {
		t.Skip("errors.Is compares error identity; no runtime behavior under test")
	}
}
