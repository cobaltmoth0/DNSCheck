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
	requestRe   = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
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

func isSinkhole(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || (ip.To4() != nil && ip.To4()[0] == 100 && ip.To4()[1]&0xC0 == 64)
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
	res := dnsResult{ips: ips, err: err, d: time.Since(t)}
	if err == nil && len(ips) == 0 {
		res.err = errors.New("empty answer")
	}
	if res.err == nil {
		res.sinkhole = true
		for _, ip := range ips {
			if !isSinkhole(ip) {
				res.sinkhole = false
			}
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
	ips = sortV4First(ips)
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

type externalNodeResult struct {
	label string
	ok    bool
	code  string
	msg   string
	sec   float64
}

// countExternalSuccesses counts only probes the provider explicitly marks successful.
// An HTTP status code alone is diagnostic information, not proof the check succeeded.
func countExternalSuccesses(results map[string]externalNodeResult) int {
	count := 0
	for _, result := range results {
		if result.ok {
			count++
		}
	}
	return count
}

// parseExternalNodeResults accepts both check-result's node map and
// check-result-extended's documented {"results": {...}} response. A nil node
// result means that node is still pending; completed nodes are retained.
func parseExternalNodeResults(raw map[string]json.RawMessage, nodes map[string][]string) (map[string]externalNodeResult, int) {
	if wrapped, ok := raw["results"]; ok {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(wrapped, &nested); err == nil && len(nested) > 0 {
			raw = nested
		}
	}
	parsed := make(map[string]externalNodeResult)
	pending := 0
	for node, rm := range raw {
		var outer []json.RawMessage
		if strings.TrimSpace(string(rm)) == "null" || json.Unmarshal(rm, &outer) != nil || len(outer) == 0 {
			pending++
			continue
		}
		var fields []any
		if len(outer) == 1 && strings.TrimSpace(string(outer[0])) == "null" {
			pending++
			continue
		}
		if json.Unmarshal(outer[0], &fields) != nil || len(fields) < 3 {
			continue
		}
		result := externalNodeResult{}
		if value, ok := fields[0].(float64); ok {
			result.ok = value == 1
		}
		result.sec, _ = fields[1].(float64)
		result.msg, _ = fields[2].(string)
		if len(fields) > 3 {
			if code, ok := fields[3].(string); ok {
				result.code = code
			}
		}
		result.label = node
		if info, ok := nodes[node]; ok && len(info) >= 3 {
			result.label = info[2] + ", " + info[0]
		}
		parsed[node] = result
	}
	return parsed, pending
}

// ---- External probe (check-host.net) ---------------------------------------

type ext struct {
	asked bool
	up    int // nodes the provider explicitly marked successful
	total int
}

func externalCheck(ctx context.Context, host string, rep *Report) ext {
	rep.set(rowExt, Running, "Asking check-host.net...", -1)
	tr := noProxyTransport()
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 48*time.Second)
	defer cancel()

	var start struct {
		OK        int                 `json:"ok"`
		RequestID string              `json:"request_id"`
		Nodes     map[string][]string `json:"nodes"`
	}
	if err := getJSON(ctx, tr, "https://check-host.net/check-http?max_nodes=3&host="+url.QueryEscape("https://"+host), &start); err != nil ||
		start.OK != 1 || !requestRe.MatchString(start.RequestID) {
		rep.set(rowExt, Info, "External checker unavailable from this network", -1)
		return ext{}
	}

	final := map[string]externalNodeResult{}
	var lastPollErr error
	validPolls := 0
	for i := 0; i < 20; i++ {
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
		if ctx.Err() != nil {
			break
		}
		var raw map[string]json.RawMessage
		// The extended endpoint explicitly documents the top-level results wrapper.
		if err := getJSON(ctx, tr, "https://check-host.net/check-result-extended/"+start.RequestID, &raw); err != nil {
			lastPollErr = err
			continue
		}
		validPolls++
		parsed, pending := parseExternalNodeResults(raw, start.Nodes)
		for node, result := range parsed {
			final[node] = result
		}
		if pending == 0 && len(final) > 0 {
			break
		}
	}

	e := ext{asked: true, total: len(final), up: countExternalSuccesses(final)}
	keys := make([]string, 0, len(final))
	var sum float64
	for k, v := range final {
		keys = append(keys, k)
		if v.ok {
			sum += v.sec * 1000
		}
	}
	sort.Strings(keys)
	if e.total == 0 {
		if validPolls == 0 && lastPollErr != nil {
			rep.set(rowExt, Info, "External checker could not retrieve results (request failed)", -1)
		} else {
			rep.set(rowExt, Info, "External checker returned no completed results; try again", -1)
		}
		return e
	}
	rows := make([]Row, 0, len(keys))
	okN := 0
	for _, k := range keys {
		v := final[k]
		st, det := Fail, v.msg
		if v.code != "" {
			det = v.code + " " + v.msg
		}
		if v.ok {
			st = OK
			okN++
		} else if v.code != "" {
			st = Info
		}
		rows = append(rows, Row{Name: "  " + v.label, Status: st, Detail: det, Ms: v.sec * 1000})
	}
	rep.mu.Lock()
	rep.Rows = append(rep.Rows[:rowExt+1], rows...)
	rep.mu.Unlock()
	switch {
	case e.up == 0:
		rep.set(rowExt, Fail, fmt.Sprintf("Unreachable from outside (0 of %d locations)", e.total), -1)
	default:
		avg := -1.0
		if okN > 0 {
			avg = sum / float64(okN)
		}
		rep.set(rowExt, OK, fmt.Sprintf("Reachable from outside (%d of %d locations)", e.up, e.total), avg)
	}
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
	extDown := e.asked && e.total > 0 && e.up == 0
	extUp := e.asked && e.up > 0

	localOK := !l.dnsFail && l.pathTested && !l.tcpFail && !l.tlsFail && !l.blockPage && l.httpOK
	if localOK {
		m := msgPassed
		if extDown {
			m += " Note: the external checker could not reach this site from outside either."
		}
		return VAccessible, "ACCESSIBLE", "DNS, firewall, TLS and HTTPS checks all passed", m
	}
	if extDown {
		return VBlocked, "UNREACHABLE", "Down for everyone, not a local block",
			"The external checker cannot reach this site either, so it is most likely offline or the domain does not exist."
	}
	switch {
	case l.dnsFail && !l.pathTested && l.refState == "ok":
		return VBlocked, "BLOCKED", "Blocked at the DNS level", "This network's DNS refuses or redirects the lookup."
	case l.dnsFail && !l.pathTested:
		if extUp {
			return VBlocked, "BLOCKED", "Blocked at the DNS level (likely)",
				"This network's DNS gives no answer, but the site is up externally. The public resolver could not be reached to confirm."
		}
		return VBlocked, "UNREACHABLE", "Could not resolve the domain", "No DNS answer anywhere. The domain may not exist; the external check was inconclusive."
	case l.dnsFail && l.tcpFail:
		return VBlocked, "BLOCKED", "Blocked at DNS and at the firewall", "The DNS lookup is blocked, and a direct connection to the real IP address is blocked as well."
	case l.dnsFail && l.tlsFail:
		return VBlocked, "BLOCKED", "Blocked at DNS and at the firewall", "The DNS lookup is blocked, and the firewall also interferes with the secure connection."
	case l.dnsFail && l.blockPage:
		return VBlocked, "BLOCKED", "Blocked at DNS and by a web filter", l.blockDetail
	case l.dnsFail:
		return VBlocked, "BLOCKED", "Blocked at the DNS level only", "The firewall path is open: a direct connection to the real IP works. Only DNS is blocking this domain."
	case l.tcpFail:
		return VBlocked, "BLOCKED", "Blocked at the firewall (IP / port 443)", "DNS resolves normally, but the connection is " + l.tcpDetail + "."
	case l.tlsFail && l.tlsCert:
		return VBlocked, "BLOCKED", "Intercepted by a filter (certificate)", l.tlsDetail
	case l.tlsFail:
		return VBlocked, "BLOCKED", "Blocked at the firewall (SNI / TLS inspection)", "TCP connects, but the secure handshake is cut off, which is typical of deep packet inspection."
	case l.blockPage:
		return VBlocked, "BLOCKED", "Blocked by a web filter", l.blockDetail
	}
	return VBlocked, "BLOCKED", "Request failed", "The site did not return a usable response."
}
