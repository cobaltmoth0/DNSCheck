package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Status int

const (
	Pending Status = iota
	Running
	OK
	Fail
	Info
)

type Verdict int

const (
	VNone Verdict = iota
	VAccessible
	VBlocked
)

type Row struct {
	Name   string
	Status Status
	Detail string
	Ms     float64 // < 0 means no timing
}

type Report struct {
	mu       sync.Mutex
	notify   func()
	Host     string
	Rows     []Row
	Verdict  Verdict
	Headline string
	Layer    string
	Message  string
	Done     bool
	TotalMs  float64
}

func newReport(host string, notify func()) *Report {
	r := &Report{Host: host, notify: notify}
	for _, n := range []string{"DNS (this network)", "DNS (public resolver)", "TCP 443 connect", "TLS handshake", "HTTPS response", "External check"} {
		r.Rows = append(r.Rows, Row{Name: n, Status: Pending, Ms: -1})
	}
	return r
}

func (r *Report) set(i int, st Status, detail string, ms float64) {
	r.mu.Lock()
	if i >= 0 && i < len(r.Rows) {
		r.Rows[i].Status, r.Rows[i].Detail, r.Rows[i].Ms = st, detail, ms
	}
	r.mu.Unlock()
	r.ping()
}

func (r *Report) ping() {
	if r.notify != nil {
		r.notify()
	}
}

func (r *Report) snapshot() Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Report{Host: r.Host, Rows: append([]Row(nil), r.Rows...), Verdict: r.Verdict,
		Headline: r.Headline, Layer: r.Layer, Message: r.Message, Done: r.Done, TotalMs: r.TotalMs}
}

const (
	rowDNS = iota
	rowDoH
	rowTCP
	rowTLS
	rowHTTP
	rowExt
)

const (
	msgPassed = "Network checks passed, if a domain is still blocked this most likely points to GoGuardian."
	maxBody   = 8192
)

var (
	labelRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	filterTerms = []string{"goguardian", "securly", "lightspeed", "fortiguard", "fortinet", "iboss",
		"contentkeeper", "smoothwall", "linewize", "forcepoint", "websense", "opendns", "cisco umbrella",
		"web filter", "content filter", "blocked by", "access denied by"}
)

// ParseHost accepts a bare domain or an http(s) URL and returns a validated lowercase hostname.
func ParseHost(in string) (string, error) {
	bad := errors.New("Enter a domain name such as example.com")
	s := strings.TrimSpace(in)
	if s == "" || len(s) > 2048 {
		return "", bad
	}
	if i := strings.Index(s, "://"); i >= 0 {
		if sc := strings.ToLower(s[:i]); sc != "http" && sc != "https" {
			return "", bad
		}
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if strings.ContainsAny(s, "@: \t\r\n\\[]") {
		return "", errors.New("Enter only the domain name (no port, login or spaces)")
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if len(s) > 253 || !strings.Contains(s, ".") {
		return "", bad
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", errors.New("Not a valid ASCII domain name (use punycode for international names)")
		}
	}
	if tld := labels[len(labels)-1]; strings.Trim(tld, "0123456789") == "" {
		return "", errors.New("IP addresses are not supported, enter a domain name")
	}
	return s, nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func isSinkhole(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	for _, prefix := range reservedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return !addr.IsGlobalUnicast() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsMulticast()
}

func filterSafeIPs(ips []net.IP) (safe, unsafe []net.IP) {
	for _, ip := range ips {
		if isSinkhole(ip) {
			unsafe = append(unsafe, ip)
		} else {
			safe = append(safe, ip)
		}
	}
	return safe, unsafe
}

func ipList(ips []net.IP) string {
	s := make([]string, 0, len(ips))
	for _, ip := range ips {
		s = append(s, ip.String())
	}
	if len(s) > 2 {
		return fmt.Sprintf("%s, %s (+%d more)", s[0], s[1], len(s)-2)
	}
	return strings.Join(s, ", ")
}

func sortV4First(ips []net.IP) []net.IP {
	out := append([]net.IP(nil), ips...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].To4() != nil && out[j].To4() == nil })
	return out
}

func noProxyTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 6 * time.Second,
		DisableKeepAlives:     true,
	}
}

func getJSON(ctx context.Context, tr *http.Transport, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "DNSCheck/1.0")
	c := &http.Client{Transport: tr, Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(v)
}

// ---- DNS -------------------------------------------------------------------

type dnsResult struct {
	ips      []net.IP
	err      error
	sinkhole bool
	d        time.Duration
	via      string
}

func lookupSystem(ctx context.Context, host string) dnsResult {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	t := time.Now()
	ips, err := (&net.Resolver{}).LookupIP(ctx, "ip", host)
	res := dnsResult{err: err, d: time.Since(t)}
	if err == nil && len(ips) == 0 {
		res.err = errors.New("empty answer")
	}
	if res.err == nil {
		var unsafe []net.IP
		res.ips, unsafe = filterSafeIPs(ips)
		if len(res.ips) == 0 && len(unsafe) > 0 {
			res.sinkhole = true
			res.ips = unsafe
		}
	}
	return res
}

func lookupDoH(ctx context.Context, host string) dnsResult {
	var last dnsResult
	tr := noProxyTransport()
	defer tr.CloseIdleConnections()
	for _, ep := range []struct{ name, base string }{
		{"1.1.1.1", "https://1.1.1.1/dns-query"},
		{"8.8.8.8", "https://8.8.8.8/resolve"},
	} {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		t := time.Now()
		var out struct {
			Status int `json:"Status"`
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		err := getJSON(cctx, tr, ep.base+"?type=A&name="+url.QueryEscape(host), &out)
		cancel()
		res := dnsResult{err: err, d: time.Since(t), via: ep.name}
		if err == nil {
			for _, a := range out.Answer {
				if ip := net.ParseIP(a.Data); a.Type == 1 && ip != nil {
					res.ips = append(res.ips, ip)
				}
			}
			if len(res.ips) == 0 {
				res.err = errNoAnswer
			}
			return res
		}
		last = res
	}
	return last
}

var errNoAnswer = errors.New("no answer")

// ---- TCP / TLS / HTTP ------------------------------------------------------

func dialAny(ctx context.Context, ips []net.IP) (net.Conn, net.IP, time.Duration, error) {
	var lastErr error
	// Apply the same deny policy at the final network boundary.
	safe, _ := filterSafeIPs(ips)
	ips = sortV4First(safe)
	if len(ips) == 0 {
		return nil, nil, 0, errors.New("no globally routable address")
	}
	if len(ips) > 3 {
		ips = ips[:3]
	}
	var total time.Duration
	for _, ip := range ips {
		t := time.Now()
		c, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
		total += time.Since(t)
		if err == nil {
			return c, ip, time.Since(t), nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, nil, total, lastErr
}

func describeNetErr(err error) string {
	var ne net.Error
	s := strings.ToLower(err.Error())
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "timed out (packets silently dropped)"
	case strings.Contains(s, "refused"):
		return "actively refused"
	case strings.Contains(s, "reset"):
		return "connection reset"
	case strings.Contains(s, "unreachable"):
		return "network unreachable"
	case errors.Is(err, io.EOF):
		return "closed by remote"
	}
	return "failed"
}

func containsFilterTerm(s string) string {
	s = strings.ToLower(s)
	for _, t := range filterTerms {
		if strings.Contains(s, t) {
			return t
		}
	}
	return ""
}

type local struct {
	dnsFail     bool // system DNS blocked or sinkholed
	dnsNote     string
	refState    string // ok, empty, down
	pathTested  bool
	tcpFail     bool
	tlsFail     bool
	tlsCert     bool
	blockPage   bool
	httpOK      bool
	tcpDetail   string
	tlsDetail   string
	blockDetail string
}

func runLocal(ctx context.Context, host string, rep *Report) local {
	var l local
	var sys, ref dnsResult
	rep.set(rowDNS, Running, "Resolving...", -1)
	rep.set(rowDoH, Running, "Resolving...", -1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sys = lookupSystem(ctx, host)
		switch {
		case sys.err != nil:
			rep.set(rowDNS, Fail, "No answer (blocked, NXDOMAIN or timeout)", ms(sys.d))
		case sys.sinkhole:
			rep.set(rowDNS, Fail, "Sinkholed: "+ipList(sys.ips), ms(sys.d))
		default:
			rep.set(rowDNS, OK, ipList(sys.ips), ms(sys.d))
		}
	}()
	go func() {
		defer wg.Done()
		ref = lookupDoH(ctx, host)
		switch {
		case ref.err == nil:
			rep.set(rowDoH, OK, ipList(ref.ips)+" via "+ref.via, ms(ref.d))
		case errors.Is(ref.err, errNoAnswer):
			rep.set(rowDoH, Info, "No answer from "+ref.via+" (domain may not exist)", ms(ref.d))
		default:
			rep.set(rowDoH, Info, "Public resolver unreachable (DoH blocked?)", -1)
		}
	}()
	wg.Wait()

	switch {
	case ref.err == nil:
		l.refState = "ok"
	case errors.Is(ref.err, errNoAnswer):
		l.refState = "empty"
	default:
		l.refState = "down"
	}
	l.dnsFail = sys.err != nil || sys.sinkhole

	var ips []net.IP
	switch {
	case !l.dnsFail:
		ips = sys.ips
	case l.refState == "ok":
		ips = ref.ips
	default:
		for i := rowTCP; i <= rowHTTP; i++ {
			rep.set(i, Info, "Skipped (no address to test)", -1)
		}
		return l
	}
	l.pathTested = true
	suffix := ""
	if l.dnsFail {
		suffix = " (direct to public IP)"
	}

	rep.set(rowTCP, Running, "Connecting...", -1)
	conn, ip, d, err := dialAny(ctx, ips)
	if err != nil {
		l.tcpFail = true
		l.tcpDetail = describeNetErr(err)
		rep.set(rowTCP, Fail, "Connection "+l.tcpDetail+suffix, ms(d))
		for i := rowTLS; i <= rowHTTP; i++ {
			rep.set(i, Info, "Skipped", -1)
		}
		return l
	}
	defer conn.Close()
	rep.set(rowTCP, OK, "Connected to "+ip.String()+suffix, ms(d))

	rep.set(rowTLS, Running, "Handshaking...", -1)
	tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	hctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	t := time.Now()
	err = tc.HandshakeContext(hctx)
	cancel()
	d = time.Since(t)
	if err != nil {
		l.tlsFail = true
		var ua x509.UnknownAuthorityError
		var he x509.HostnameError
		var ci x509.CertificateInvalidError
		switch {
		case errors.As(err, &ua):
			l.tlsCert, l.tlsDetail = true, "Untrusted certificate (filter interception or block page?)"
		case errors.As(err, &he):
			l.tlsCert, l.tlsDetail = true, "Certificate does not match the domain (block page?)"
		case errors.As(err, &ci):
			l.tlsCert, l.tlsDetail = true, "Invalid certificate"
		default:
			l.tlsDetail = "Handshake " + describeNetErr(err) + " after TCP succeeded"
		}
		rep.set(rowTLS, Fail, l.tlsDetail+suffix, ms(d))
		rep.set(rowHTTP, Info, "Skipped", -1)
		return l
	}
	issuer := ""
	if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 {
		issuer = st.PeerCertificates[0].Issuer.CommonName
		if issuer == "" && len(st.PeerCertificates[0].Issuer.Organization) > 0 {
			issuer = st.PeerCertificates[0].Issuer.Organization[0]
		}
	}
	det := "Secure session established"
	if issuer != "" {
		det += ", issuer: " + issuer
	}
	if t := containsFilterTerm(issuer); t != "" {
		l.blockPage, l.blockDetail = true, "Certificate issued by a web filter ("+issuer+")"
	}
	rep.set(rowTLS, OK, det, ms(d))

	rep.set(rowHTTP, Running, "Requesting...", -1)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; DNSCheck/1.0)")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	t = time.Now()
	if err = req.Write(tc); err != nil {
		rep.set(rowHTTP, Fail, "Request failed: "+describeNetErr(err), ms(time.Since(t)))
		return l
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(tc, 1<<20)), req)
	if err != nil {
		rep.set(rowHTTP, Fail, "No response: "+describeNetErr(err)+suffix, ms(time.Since(t)))
		return l
	}
	ttfb := time.Since(t)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	resp.Body.Close()
	total := time.Since(t)

	loc := resp.Header.Get("Location")
	if lu, e := url.Parse(loc); e == nil && lu.Hostname() != "" {
		if term := containsFilterTerm(lu.Hostname()); term != "" {
			l.blockPage, l.blockDetail = true, "Redirected to a web filter ("+lu.Hostname()+")"
		}
	}
	if !l.blockPage {
		if term := containsFilterTerm(string(body) + " " + resp.Header.Get("Server")); term != "" && (resp.StatusCode == 403 || resp.StatusCode == 451 || resp.StatusCode == 200) {
			l.blockPage, l.blockDetail = true, "Block page detected (\""+term+"\")"
		}
	}
	code := fmt.Sprintf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	switch {
	case l.blockPage:
		rep.set(rowHTTP, Fail, code+" - "+l.blockDetail, ms(ttfb))
	case resp.StatusCode == 451:
		l.blockPage, l.blockDetail = true, "HTTP 451 (blocked for legal reasons)"
		rep.set(rowHTTP, Fail, code, ms(ttfb))
	case resp.StatusCode >= 500:
		rep.set(rowHTTP, Info, code+" (server-side error)", ms(ttfb))
		l.httpOK = true
	default:
		l.httpOK = true
		rep.set(rowHTTP, OK, fmt.Sprintf("%s, first byte %.0f ms, total %.0f ms", code, ms(ttfb), ms(total)), ms(ttfb))
	}
	return l
}

// ---- External probe (Globalping) -------------------------------------------

type ext struct {
	asked bool
	up    int // probes that returned an HTTP status
	total int // probes that completed with an HTTP status
}

func isReachableHTTPResult(status string, code int) bool {
	return status == "finished" && code >= 100 && code <= 599
}

func externalCheck(ctx context.Context, host string, rep *Report) ext {
	rep.set(rowExt, Running, "Checking from Globalping locations...", -1)
	tr := noProxyTransport()
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()

	// Globalping is a public, unauthenticated distributed HTTP measurement API.
	// Request a small number of probes to keep checks quick and within free limits.
	request := map[string]any{
		"type": "http",
		"target": host,
		"locations": []map[string]any{
			{"country": "US", "limit": 2},
			{"country": "DE", "limit": 1},
		},
		"inProgressUpdates": true,
		"timeout": 8,
		"measurementOptions": map[string]any{
			"protocol": "HTTPS",
			"request": map[string]any{"method": "GET"},
		},
	}
	body, err := json.Marshal(request)
	if err != nil {
		rep.set(rowExt, Info, "External checker could not create request", -1)
		return ext{}
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.globalping.io/v1/measurements", strings.NewReader(string(body)))
	if err != nil {
		rep.set(rowExt, Info, "External checker could not create request", -1)
		return ext{}
	}
	postReq.Header.Set("Accept", "application/json")
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("User-Agent", "DNSCheck/1.0")
	client := &http.Client{Transport: tr, Timeout: 7 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(postReq)
	if err != nil {
		rep.set(rowExt, Info, "Globalping unavailable from this network", -1)
		return ext{}
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	resp.Body.Close()
	var created struct {
		ID string `json:"id"`
	}
	decodeErr := json.Unmarshal(responseBody, &created)
	if (resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK) || readErr != nil || decodeErr != nil || created.ID == "" || !regexp.MustCompile(`^[a-zA-Z0-9-]+$`).MatchString(created.ID) {
		if resp.StatusCode == http.StatusTooManyRequests {
			rep.set(rowExt, Info, "Globalping rate limit reached; try again shortly", -1)
		} else {
			var apiErr struct {
				Error struct { Message string `json:"message"` } `json:"error"`
			}
			_ = json.Unmarshal(responseBody, &apiErr)
			message := strings.TrimSpace(apiErr.Error.Message)
			if message != "" {
				rep.set(rowExt, Info, fmt.Sprintf("Globalping request failed (HTTP %d: %s)", resp.StatusCode, message), -1)
			} else {
				rep.set(rowExt, Info, fmt.Sprintf("Globalping request failed (HTTP %d)", resp.StatusCode), -1)
			}
		}
		return ext{}
	}

	type measurementResult struct {
		Probe struct {
			Country string `json:"country"`
			City string `json:"city"`
			Network string `json:"network"`
			Location struct {
				Country string `json:"country"`
				City string `json:"city"`
				Network string `json:"network"`
			} `json:"location"`
		} `json:"probe"`
		Result struct {
			Status string `json:"status"`
			StatusCode int `json:"statusCode"`
			StatusCodeName string `json:"statusCodeName"`
			RawOutput string `json:"rawOutput"`
			Timings struct { Total float64 `json:"total"` } `json:"timings"`
		} `json:"result"`
	}
	type measurement struct {
		Status string `json:"status"`
		Results []measurementResult `json:"results"`
	}
	var final measurement
	pollClient := &http.Client{Transport: tr, Timeout: 4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for i := 0; i < 12; i++ {
		var wait time.Duration
		if i == 0 { wait = 250 * time.Millisecond } else { wait = 500 * time.Millisecond }
		select {
		case <-ctx.Done():
			i = 12
			continue
		case <-time.After(wait):
		}
		getReq, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.globalping.io/v1/measurements/"+created.ID, nil)
		if reqErr != nil { continue }
		getReq.Header.Set("Accept", "application/json")
		getReq.Header.Set("User-Agent", "DNSCheck/1.0")
		getResp, getErr := pollClient.Do(getReq)
		if getErr != nil { continue }
		var current measurement
		decodeErr := json.NewDecoder(io.LimitReader(getResp.Body, 512<<10)).Decode(&current)
		getResp.Body.Close()
		if decodeErr != nil || getResp.StatusCode != http.StatusOK { continue }
		final = current
		if current.Status != "in-progress" { break }
	}

	// The request asks for three probes; cap untrusted API output accordingly.
	if len(final.Results) > 3 {
		final.Results = final.Results[:3]
	}
	e := ext{asked: true}
	rows := make([]Row, 0, len(final.Results))
	okN := 0
	var sum float64
	for _, item := range final.Results {
		if item.Result.Status == "in-progress" { continue }
		label := strings.TrimSpace(item.Probe.Location.City + ", " + item.Probe.Location.Country)
		if label == "," || label == "" { label = item.Probe.Location.Network }
		if label == "" { label = strings.TrimSpace(item.Probe.City + ", " + item.Probe.Country) }
		if label == "," { label = item.Probe.Network }
		if label == "" { label = "Globalping probe" }
		code := item.Result.StatusCode
		reachable := isReachableHTTPResult(item.Result.Status, code)
		ok := reachable && code >= 200 && code < 400
		detail := strings.TrimSpace(fmt.Sprintf("%d %s", code, item.Result.StatusCodeName))
		if code == 0 { detail = strings.TrimSpace(item.Result.RawOutput) }
		status := Info
		if ok { status = OK }
		rows = append(rows, Row{Name: "  " + label, Status: status, Detail: detail, Ms: item.Result.Timings.Total})
		if reachable {
			e.total++
			e.up++
			okN++
			sum += item.Result.Timings.Total
		}
	}
	if e.total == 0 {
		rep.set(rowExt, Info, "Globalping returned no completed HTTP responses; external reachability is inconclusive", -1)
		return e
	}
	rep.mu.Lock()
	rep.Rows = append(rep.Rows[:rowExt+1], rows...)
	rep.mu.Unlock()
	avg := -1.0
	if okN > 0 { avg = sum / float64(okN) }
	rep.set(rowExt, OK, fmt.Sprintf("HTTP response from outside (%d of %d locations)", e.up, e.total), avg)
	return e
}

// ---- Verdict ---------------------------------------------------------------

func Run(ctx context.Context, host string, rep *Report) {
	start := time.Now()
	ch := make(chan ext, 1)
	go func() { ch <- externalCheck(ctx, host, rep) }()
	l := runLocal(ctx, host, rep)
	e := <-ch

	v, head, layer, msg := conclude(l, e)
	rep.mu.Lock()
	rep.Verdict, rep.Headline, rep.Layer, rep.Message = v, head, layer, msg
	rep.TotalMs = ms(time.Since(start))
	rep.Done = true
	rep.mu.Unlock()
	rep.ping()
}

func conclude(l local, e ext) (Verdict, string, string, string) {
	extUp := e.asked && e.up > 0

	localOK := !l.dnsFail && l.pathTested && !l.tcpFail && !l.tlsFail && !l.blockPage && l.httpOK
	if localOK {
		m := msgPassed
		return VAccessible, "ACCESSIBLE", "DNS, firewall, TLS and HTTPS checks all passed", m
	}
	switch {
	case l.dnsFail && !l.pathTested && l.refState == "ok":
		return VBlocked, "BLOCKED", "Blocked at the DNS level", "This network's DNS refuses or redirects the lookup."
	case l.dnsFail && !l.pathTested:
		if extUp {
			return VBlocked, "BLOCKED", "Blocked at the DNS level (likely)",
				"This network's DNS gives no answer, but the site is up externally. The public resolver could not be reached to confirm."
		}
		return VNone, "CHECK INCONCLUSIVE", "Could not resolve the domain", "No usable DNS answer was available; the domain may not exist or DNS may be unavailable."
	case l.dnsFail && l.tcpFail:
		if extUp {
			return VBlocked, "BLOCKED", "DNS and connection failure on this network (likely)", "The external check got an HTTP response, but DNS and TCP checks failed on this network."
		}
		return VNone, "CHECK INCONCLUSIVE", "DNS and connection checks failed", "The domain may be unavailable, or this network may be blocking it; external results did not confirm reachability."
	case l.dnsFail && l.tlsFail && l.tlsCert:
		return VBlocked, "BLOCKED", "Intercepted by a filter (certificate)", l.tlsDetail
	case l.dnsFail && l.tlsFail:
		if extUp {
			return VBlocked, "BLOCKED", "TLS failure on this network (likely)", "The external check got an HTTP response, but this network could not complete the TLS handshake."
		}
		return VNone, "CHECK INCONCLUSIVE", "TLS handshake failed", "The DNS lookup and TLS handshake failed; this does not establish whether the site is down or locally blocked."
	case l.dnsFail && l.blockPage:
		return VBlocked, "BLOCKED", "Blocked at DNS and by a web filter", l.blockDetail
	case l.dnsFail:
		return VBlocked, "BLOCKED", "Blocked at the DNS level only", "The firewall path is open: a direct connection to the real IP works. Only DNS is blocking this domain."
	case l.tcpFail:
		if extUp {
			return VBlocked, "BLOCKED", "Connection failure on this network (likely)", "The external check got an HTTP response, but the local TCP connection failed."
		}
		return VNone, "CONNECTION FAILED", "Could not connect to the resolved address", "DNS resolved normally, but the TCP connection failed. This alone does not prove a firewall block."
	case l.tlsFail && l.tlsCert:
		return VBlocked, "BLOCKED", "Intercepted by a filter (certificate)", l.tlsDetail
	case l.tlsFail:
		if extUp {
			return VBlocked, "BLOCKED", "TLS failure on this network (likely)", "The external check got an HTTP response, but this network could not complete the TLS handshake."
		}
		return VNone, "TLS FAILED", "The secure connection could not be established", "TCP connected, but the TLS handshake failed. This alone does not identify the cause."
	case l.blockPage:
		return VBlocked, "BLOCKED", "Blocked by a web filter", l.blockDetail
	}
	return VNone, "CHECK INCONCLUSIVE", "Request failed", "The site did not return a usable response; this result does not prove that it is blocked."
}
