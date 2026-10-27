package main

import "testing"

func TestPipelineIconFilesMatchNetworkStages(t *testing.T) {
	tests := []struct {
		stage int
		want  string
	}{
		{pipelineComputer, "Computer.png"},
		{pipelineDNS, "dns.png"},
		{pipelineFirewall, "firewall.png"},
		{pipelineInternet, "internet.png"},
		{pipelineBlock, "connect_fail.png"},
	}

	for _, test := range tests {
		if got := pipelineIconFile(test.stage); got != test.want {
			t.Errorf("pipelineIconFile(%d) = %q, want %q", test.stage, got, test.want)
		}
	}
	if got := pipelineIconFile(-1); got != "" {
		t.Errorf("pipelineIconFile(-1) = %q, want empty", got)
	}
}

func TestPipelineBlockOverlayOnlyCoversFailedStages(t *testing.T) {
	for _, status := range []Status{Pending, Running, OK, Info} {
		if pipelineNeedsBlockOverlay(status) {
			t.Errorf("pipelineNeedsBlockOverlay(%v) = true, want false", status)
		}
	}
	if !pipelineNeedsBlockOverlay(Fail) {
		t.Error("pipelineNeedsBlockOverlay(Fail) = false, want true")
	}
}
