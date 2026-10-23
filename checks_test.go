package main

import (
	"encoding/json"
	"net"
	"testing"
)

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

