package main

import (
	"context"
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

func TestDialAnyRejectsUnsafeAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "fc00::1"} {
		t.Run(address, func(t *testing.T) {
			ip := net.ParseIP(address)
			if _, _, _, err := dialAny(context.Background(), []net.IP{ip}); err == nil {
				t.Fatalf("dialAny(%q) unexpectedly allowed a non-public address", address)
			}
		})
	}
}

func TestIsSinkhole(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.2", "0.0.0.0", "224.0.0.1", "fc00::1", "100.64.0.1", "192.0.2.1", "198.18.0.1", "240.0.0.1", "2001:db8::1", "64:ff9b::808:808", "::ffff:10.0.0.1"} {
		if parsed := net.ParseIP(ip); parsed == nil || !isSinkhole(parsed) {
			t.Errorf("isSinkhole(%q) = false, want true", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"} {
		if parsed := net.ParseIP(ip); parsed == nil || isSinkhole(parsed) {
			t.Errorf("isSinkhole(%q) = true, want false", ip)
		}
	}
	if !isSinkhole(net.IP{1, 2, 3}) {
		t.Error("isSinkhole() = false for an invalid IP, want true")
	}
}

func TestIsReachableHTTPResult(t *testing.T) {
	for _, test := range []struct {
		status string
		code   int
		want   bool
	}{
		{status: "finished", code: 200, want: true},
		{status: "finished", code: 404, want: true},
		{status: "finished", code: 503, want: true},
		{status: "failed", code: 0, want: false},
		{status: "finished", code: 0, want: false},
	} {
		if got := isReachableHTTPResult(test.status, test.code); got != test.want {
			t.Errorf("isReachableHTTPResult(%q, %d) = %t, want %t", test.status, test.code, got, test.want)
		}
	}
}

func TestFilterSafeIPsKeepsPublicAnswers(t *testing.T) {
	ips := []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), net.ParseIP("192.0.2.1")}
	safe, unsafe := filterSafeIPs(ips)
	if len(safe) != 1 || !safe[0].Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("safe addresses = %v, want only 8.8.8.8", safe)
	}
	if len(unsafe) != 2 {
		t.Fatalf("unsafe addresses = %v, want two rejected addresses", unsafe)
	}
}

func TestLocalBlockEvidenceIsNotOverriddenByExternalFailure(t *testing.T) {
	localResult := local{blockPage: true, blockDetail: "Block page detected", pathTested: true}
	verdict, headline, _, _ := conclude(localResult, ext{asked: true, total: 1, up: 0})
	if verdict != VBlocked || headline != "Blocked by a web filter" {
		t.Fatalf("conclude() = (%v, %q), want local block diagnosis", verdict, headline)
	}
}

