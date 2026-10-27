package main

const (
	pipelineComputer = iota
	pipelineDNS
	pipelineFirewall
	pipelineInternet
	pipelineBlock
)

var pipelineIconFiles = [...]string{
	"Computer.png",
	"dns.png",
	"firewall.png",
	"internet.png",
	"connect_fail.png",
}

func pipelineIconFile(kind int) string {
	if kind < 0 || kind >= len(pipelineIconFiles) {
		return ""
	}
	return pipelineIconFiles[kind]
}

func pipelineNeedsBlockOverlay(st Status) bool {
	return st == Fail
}
