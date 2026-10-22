//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

// Console harness for developers on non-Windows systems; the shipped app is the Windows GUI.
func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: dnscheck <domain>")
		os.Exit(2)
	}
	host, err := ParseHost(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	rep := newReport(host, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	Run(ctx, host, rep)
	s := rep.snapshot()
	for _, r := range s.Rows {
		fmt.Printf("%-24s %d %8.1f ms  %s\n", r.Name, r.Status, r.Ms, r.Detail)
	}
	fmt.Println(s.Headline, "|", s.Layer, "|", s.Message)
}
