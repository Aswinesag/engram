package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultDialTimeout        = 15 * time.Second
	DefaultMaxInspectBodySize = 10 << 20 // 10 MiB
)

// SecretAction controls how the HTTP egress proxy responds when a secret is detected.
type SecretAction string

const (
	// SecretActionBlock rejects the outbound request with HTTP 403 Forbidden (default).
	SecretActionBlock SecretAction = "block"
	// SecretActionRedact replaces detected secrets with [REDACTED:<rule>] before forwarding.
	SecretActionRedact SecretAction = "redact"
)

// AuditEvent captures a single proxy allow/block decision for telemetry and observability.
type AuditEvent struct {
	Timestamp   time.Time
	Protocol    string // "http", "connect", "socks5"
	Target      string
	Allowed     bool
	Reason      string
	SecretRules []string
}

// ProxyStats reports atomic proxy counters.
type ProxyStats struct {
	AllowedCount       int64
	BlockedDomainCount int64
	BlockedSecretCount int64
	RedactedCount      int64
}

// ProxyConfig configures the local HTTP + SOCKS5 egress proxy.
type ProxyConfig struct {
	ListenHost         string
	HTTPPort           int
	SOCKS5Port         int
	AllowedDomains     []string
	Scrubber           *Scrubber
	SecretAction       SecretAction
	MaxInspectBodySize int64
	DialContext        func(ctx context.Context, network, addr string) (net.Conn, error)
	OnEvent            func(AuditEvent)
}

// DomainAllowlist enforces default-deny domain and wildcard allowlist matching.
type DomainAllowlist struct {
	exact     map[string]struct{}
	wildcards []string // stored as ".example.com"
}

// NewDomainAllowlist compiles per-repo allowed_domains from .engram/config.toml.
func NewDomainAllowlist(domains []string) *DomainAllowlist {
	al := &DomainAllowlist{
		exact: make(map[string]struct{}),
	}
	for _, raw := range domains {
		d := strings.ToLower(strings.TrimSpace(raw))
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			suffix := strings.TrimPrefix(d, "*")
			if len(suffix) > 1 {
				al.wildcards = append(al.wildcards, suffix)
			}
			continue
		}
		al.exact[d] = struct{}{}
	}
	return al
}

// Allows returns true only if host matches an exact entry or wildcard suffix.
// Raw IP addresses are rejected unless explicitly listed in AllowedDomains.
func (a *DomainAllowlist) Allows(host string) bool {
	if a == nil {
		return false
	}
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	if _, ok := a.exact[h]; ok {
		return true
	}
	// Never match wildcard domain rules against raw IP literals.
	if net.ParseIP(h) != nil {
		return false
	}
	for _, suffix := range a.wildcards {
		if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
			return true
		}
	}
	return false
}

// EgressProxy runs local HTTP (plain + CONNECT) and RFC 1928 SOCKS5 listeners
// enforcing per-repo domain allowlists and secret leak prevention.
type EgressProxy struct {
	cfg       ProxyConfig
	allowlist *DomainAllowlist
	scrubber  *Scrubber
	action    SecretAction
	maxBody   int64
	dialCtx   func(ctx context.Context, network, addr string) (net.Conn, error)
	transport *http.Transport

	mu            sync.Mutex
	started       bool
	closed        bool
	httpListener  net.Listener
	socksListener net.Listener
	httpServer    *http.Server
	socksWG       sync.WaitGroup
	stopCh        chan struct{}

	allowedCount       atomic.Int64
	blockedDomainCount atomic.Int64
	blockedSecretCount atomic.Int64
	redactedCount      atomic.Int64
}

// NewEgressProxy creates an EgressProxy ready to be started via Start.
func NewEgressProxy(cfg ProxyConfig) (*EgressProxy, error) {
	if strings.TrimSpace(cfg.ListenHost) == "" {
		cfg.ListenHost = "127.0.0.1"
	}
	action := cfg.SecretAction
	if action == "" {
		action = SecretActionBlock
	}
	if action != SecretActionBlock && action != SecretActionRedact {
		return nil, fmt.Errorf("proxy: unsupported SecretAction %q", action)
	}
	maxBody := cfg.MaxInspectBodySize
	if maxBody <= 0 {
		maxBody = DefaultMaxInspectBodySize
	}

	dialFn := cfg.DialContext
	if dialFn == nil {
		d := &net.Dialer{
			Timeout:   DefaultDialTimeout,
			KeepAlive: 30 * time.Second,
		}
		dialFn = d.DialContext
	}

	// Explicitly disable environment proxy lookup on the upstream transport so
	// the proxy never recurses onto itself when HTTP_PROXY is set.
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialFn,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          64,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &EgressProxy{
		cfg:       cfg,
		allowlist: NewDomainAllowlist(cfg.AllowedDomains),
		scrubber:  cfg.Scrubber,
		action:    action,
		maxBody:   maxBody,
		dialCtx:   dialFn,
		transport: tr,
		stopCh:    make(chan struct{}),
	}, nil
}

// Start binds the HTTP and SOCKS5 listeners and begins serving proxy traffic.
func (p *EgressProxy) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.started {
		return errors.New("proxy: already started")
	}
	if p.closed {
		return errors.New("proxy: already closed")
	}

	lc := net.ListenConfig{}
	httpBind := net.JoinHostPort(p.cfg.ListenHost, strconv.Itoa(p.cfg.HTTPPort))
	httpLn, err := lc.Listen(ctx, "tcp", httpBind)
	if err != nil {
		return fmt.Errorf("proxy: listen HTTP on %s: %w", httpBind, err)
	}

	socksBind := net.JoinHostPort(p.cfg.ListenHost, strconv.Itoa(p.cfg.SOCKS5Port))
	socksLn, err := lc.Listen(ctx, "tcp", socksBind)
	if err != nil {
		_ = httpLn.Close()
		return fmt.Errorf("proxy: listen SOCKS5 on %s: %w", socksBind, err)
	}

	p.httpListener = httpLn
	p.socksListener = socksLn
	p.httpServer = &http.Server{
		Handler:           http.HandlerFunc(p.handleHTTP),
		ReadHeaderTimeout: 15 * time.Second,
	}
	p.started = true

	go func() {
		_ = p.httpServer.Serve(httpLn)
	}()

	p.socksWG.Add(1)
	go func() {
		defer p.socksWG.Done()
		p.serveSOCKS5(socksLn)
	}()

	return nil
}

// Close shuts down both HTTP and SOCKS5 listeners cleanly.
func (p *EgressProxy) Close(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	started := p.started
	httpSrv := p.httpServer
	socksLn := p.socksListener
	close(p.stopCh)
	p.mu.Unlock()

	if !started {
		return nil
	}

	var errs []error
	if socksLn != nil {
		if err := socksLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("proxy: close socks5 listener: %w", err))
		}
	}
	if httpSrv != nil {
		if err := httpSrv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, fmt.Errorf("proxy: shutdown http server: %w", err))
		}
	}
	p.transport.CloseIdleConnections()
	p.socksWG.Wait()
	return errors.Join(errs...)
}

// HTTPAddr returns the bound host:port of the HTTP/CONNECT proxy listener.
func (p *EgressProxy) HTTPAddr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.httpListener == nil {
		return ""
	}
	return p.httpListener.Addr().String()
}

// HTTPURL returns the HTTP proxy URL (http://host:port).
func (p *EgressProxy) HTTPURL() string {
	addr := p.HTTPAddr()
	if addr == "" {
		return ""
	}
	return "http://" + addr
}

// SOCKS5Addr returns the bound host:port of the SOCKS5 proxy listener.
func (p *EgressProxy) SOCKS5Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.socksListener == nil {
		return ""
	}
	return p.socksListener.Addr().String()
}

// SOCKS5URL returns the SOCKS5 proxy URL with remote DNS resolution (socks5h://host:port).
func (p *EgressProxy) SOCKS5URL() string {
	addr := p.SOCKS5Addr()
	if addr == "" {
		return ""
	}
	return "socks5h://" + addr
}

// ProxyEnv returns standard environment variables routing sandboxed traffic through this proxy.
func (p *EgressProxy) ProxyEnv() []string {
	httpURL := p.HTTPURL()
	socksURL := p.SOCKS5URL()
	if httpURL == "" || socksURL == "" {
		return nil
	}
	return []string{
		"HTTP_PROXY=" + httpURL,
		"HTTPS_PROXY=" + httpURL,
		"ALL_PROXY=" + socksURL,
		"http_proxy=" + httpURL,
		"https_proxy=" + httpURL,
		"all_proxy=" + socksURL,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
	}
}

// Stats returns a snapshot of allow/block/redaction counters.
func (p *EgressProxy) Stats() ProxyStats {
	return ProxyStats{
		AllowedCount:       p.allowedCount.Load(),
		BlockedDomainCount: p.blockedDomainCount.Load(),
		BlockedSecretCount: p.blockedSecretCount.Load(),
		RedactedCount:      p.redactedCount.Load(),
	}
}

// IsDomainAllowed checks host against the configured per-repo allowlist.
func (p *EgressProxy) IsDomainAllowed(host string) bool {
	return p.allowlist.Allows(host)
}

func (p *EgressProxy) emitEvent(ev AuditEvent) {
	ev.Timestamp = time.Now().UTC()
	if p.cfg.OnEvent != nil {
		p.cfg.OnEvent(ev)
	}
}

// --- HTTP & CONNECT Handler ---

func (p *EgressProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlainHTTP(w, r)
}

func (p *EgressProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetAddr := r.Host
	if targetAddr == "" {
		targetAddr = r.URL.Host
	}
	host, port := splitHostPortDefault(targetAddr, "443")
	if host == "" {
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}

	if !p.allowlist.Allows(host) {
		p.blockedDomainCount.Add(1)
		p.emitEvent(AuditEvent{
			Protocol: "connect",
			Target:   host,
			Allowed:  false,
			Reason:   "domain not in allowlist",
		})
		http.Error(w, fmt.Sprintf("engram egress proxy: domain %q is not in allowed_domains", host), http.StatusForbidden)
		return
	}

	// Scan CONNECT request headers for leaked secrets before dialing upstream.
	if p.scrubber != nil {
		if rules := p.scanHeaders(r.Header); len(rules) > 0 {
			p.blockedSecretCount.Add(1)
			p.emitEvent(AuditEvent{
				Protocol:    "connect",
				Target:      host,
				Allowed:     false,
				Reason:      "secret detected in CONNECT headers",
				SecretRules: rules,
			})
			http.Error(w, fmt.Sprintf("engram egress proxy: blocked secret leak in CONNECT headers (%s)", strings.Join(rules, ", ")), http.StatusForbidden)
			return
		}
	}

	upstreamConn, err := p.dialCtx(r.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		http.Error(w, fmt.Sprintf("engram egress proxy: upstream dial failed: %v", err), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstreamConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, bufRW, err := hj.Hijack()
	if err != nil {
		_ = upstreamConn.Close()
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		return
	}

	p.allowedCount.Add(1)
	p.emitEvent(AuditEvent{
		Protocol: "connect",
		Target:   net.JoinHostPort(host, port),
		Allowed:  true,
		Reason:   "allowed",
	})

	// Flush any already-buffered bytes read alongside the CONNECT request.
	if bufRW != nil && bufRW.Reader.Buffered() > 0 {
		buffered, _ := bufRW.Reader.Peek(bufRW.Reader.Buffered())
		if len(buffered) > 0 {
			_, _ = upstreamConn.Write(buffered)
		}
	}

	tunnelConns(clientConn, upstreamConn)
}

func (p *EgressProxy) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	targetHost := r.URL.Hostname()
	if targetHost == "" {
		targetHost, _ = splitHostPortDefault(r.Host, "80")
	}
	if targetHost == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}

	if !p.allowlist.Allows(targetHost) {
		p.blockedDomainCount.Add(1)
		p.emitEvent(AuditEvent{
			Protocol: "http",
			Target:   targetHost,
			Allowed:  false,
			Reason:   "domain not in allowlist",
		})
		http.Error(w, fmt.Sprintf("engram egress proxy: domain %q is not in allowed_domains", targetHost), http.StatusForbidden)
		return
	}

	var bodyBytes []byte
	if r.Body != nil {
		limited := io.LimitReader(r.Body, p.maxBody+1)
		var err error
		bodyBytes, err = io.ReadAll(limited)
		_ = r.Body.Close()
		if err != nil {
			http.Error(w, fmt.Sprintf("failed reading request body: %v", err), http.StatusBadRequest)
			return
		}
		if int64(len(bodyBytes)) > p.maxBody {
			http.Error(w, "request body exceeds inspection limit", http.StatusRequestEntityTooLarge)
			return
		}
	}

	outURL := *r.URL
	if outURL.Scheme == "" {
		outURL.Scheme = "http"
	}
	if outURL.Host == "" {
		outURL.Host = r.Host
	}

	outHeader := cloneCleanHeaders(r.Header)

	if p.scrubber != nil {
		urlRes := p.scrubber.Scrub(outURL.RequestURI())
		bodyRes := p.scrubber.Scrub(string(bodyBytes))
		hdrRules, scrubbedHeaders := p.inspectAndMaybeScrubHeaders(outHeader)

		var allRules []string
		allRules = appendUniqueRules(allRules, findingsToRules(urlRes.Findings))
		allRules = appendUniqueRules(allRules, findingsToRules(bodyRes.Findings))
		allRules = appendUniqueRules(allRules, hdrRules)

		if len(allRules) > 0 {
			if p.action == SecretActionBlock {
				p.blockedSecretCount.Add(1)
				p.emitEvent(AuditEvent{
					Protocol:    "http",
					Target:      targetHost,
					Allowed:     false,
					Reason:      "secret detected in outbound HTTP request",
					SecretRules: allRules,
				})
				http.Error(w, fmt.Sprintf("engram egress proxy: blocked outbound secret leak (%s)", strings.Join(allRules, ", ")), http.StatusForbidden)
				return
			}

			// SecretActionRedact: sanitize URL query, headers, and body before forwarding.
			p.redactedCount.Add(1)
			if !urlRes.Clean {
				if parsed, err := outURL.Parse(urlRes.Redacted); err == nil {
					outURL.Path = parsed.Path
					outURL.RawQuery = parsed.RawQuery
				}
			}
			if !bodyRes.Clean {
				bodyBytes = []byte(bodyRes.Redacted)
			}
			outHeader = scrubbedHeaders
		}
	}

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bodyReader)
	if err != nil {
		http.Error(w, fmt.Sprintf("build upstream request: %v", err), http.StatusBadRequest)
		return
	}
	outReq.Header = outHeader
	outReq.ContentLength = int64(len(bodyBytes))

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("engram egress proxy: upstream request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.allowedCount.Add(1)
	p.emitEvent(AuditEvent{
		Protocol: "http",
		Target:   targetHost,
		Allowed:  true,
		Reason:   "allowed",
	})

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// --- RFC 1928 SOCKS5 Server ---

const (
	socksVersion5          = 0x05
	socksAuthNone          = 0x00
	socksAuthNoAcceptable  = 0xFF
	socksCmdConnect        = 0x01
	socksAtypIPv4          = 0x01
	socksAtypDomain        = 0x03
	socksAtypIPv6          = 0x04
	socksRepSuccess        = 0x00
	socksRepGeneralFail    = 0x01
	socksRepNotAllowed     = 0x02
	socksRepHostUnreach    = 0x04
	socksRepConnRefused    = 0x05
	socksRepCmdUnsupported = 0x07
	socksRepAtypUnsupport  = 0x08
)

func (p *EgressProxy) serveSOCKS5(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.stopCh:
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
		}
		p.socksWG.Add(1)
		go func(c net.Conn) {
			defer p.socksWG.Done()
			p.handleSOCKS5Conn(c)
		}(conn)
	}
}

func (p *EgressProxy) handleSOCKS5Conn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// 1. Greeting: [VER, NMETHODS]
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socksVersion5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	supportsNoAuth := false
	for _, m := range methods {
		if m == socksAuthNone {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		_, _ = conn.Write([]byte{socksVersion5, socksAuthNoAcceptable})
		return
	}
	if _, err := conn.Write([]byte{socksVersion5, socksAuthNone}); err != nil {
		return
	}

	// 2. Request: [VER, CMD, RSV, ATYP]
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != socksVersion5 {
		return
	}
	if reqHdr[1] != socksCmdConnect {
		writeSOCKS5Reply(conn, socksRepCmdUnsupported)
		return
	}

	var dstHost string
	switch reqHdr[3] {
	case socksAtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		dstHost = net.IP(buf).String()
	case socksAtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		dstHost = net.IP(buf).String()
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domainBuf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		dstHost = string(domainBuf)
	default:
		writeSOCKS5Reply(conn, socksRepAtypUnsupport)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	dstPort := binary.BigEndian.Uint16(portBuf)

	if !p.allowlist.Allows(dstHost) {
		p.blockedDomainCount.Add(1)
		p.emitEvent(AuditEvent{
			Protocol: "socks5",
			Target:   dstHost,
			Allowed:  false,
			Reason:   "domain/IP not in allowlist",
		})
		writeSOCKS5Reply(conn, socksRepNotAllowed)
		return
	}

	targetAddr := net.JoinHostPort(dstHost, strconv.Itoa(int(dstPort)))
	dialCtx, cancel := context.WithTimeout(context.Background(), DefaultDialTimeout)
	upstreamConn, err := p.dialCtx(dialCtx, "tcp", targetAddr)
	cancel()
	if err != nil {
		writeSOCKS5Reply(conn, socksRepHostUnreach)
		return
	}

	if err := writeSOCKS5Reply(conn, socksRepSuccess); err != nil {
		_ = upstreamConn.Close()
		return
	}

	// Clear handshake deadline for active tunnel streaming.
	_ = conn.SetDeadline(time.Time{})

	p.allowedCount.Add(1)
	p.emitEvent(AuditEvent{
		Protocol: "socks5",
		Target:   targetAddr,
		Allowed:  true,
		Reason:   "allowed",
	})

	tunnelConns(conn, upstreamConn)
}

func writeSOCKS5Reply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{
		socksVersion5, rep, 0x00, socksAtypIPv4,
		0x00, 0x00, 0x00, 0x00, // 0.0.0.0
		0x00, 0x00, // port 0
	})
	return err
}

func tunnelConns(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyOneWay := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	go copyOneWay(a, b)
	go copyOneWay(b, a)
	wg.Wait()

	_ = a.Close()
	_ = b.Close()
}

// --- Header & Helper Utilities ---

var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailers":            {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func cloneCleanHeaders(src http.Header) http.Header {
	dst := make(http.Header, len(src))
	for k, vals := range src {
		if _, hop := hopByHopHeaders[http.CanonicalHeaderKey(k)]; hop {
			continue
		}
		cp := make([]string, len(vals))
		copy(cp, vals)
		dst[k] = cp
	}
	return dst
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		if _, hop := hopByHopHeaders[http.CanonicalHeaderKey(k)]; hop {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func (p *EgressProxy) scanHeaders(h http.Header) []string {
	var rules []string
	for k, vals := range h {
		for _, v := range vals {
			findings := p.scrubber.Scan(k + ": " + v)
			rules = appendUniqueRules(rules, findingsToRules(findings))
		}
	}
	return rules
}

func (p *EgressProxy) inspectAndMaybeScrubHeaders(h http.Header) ([]string, http.Header) {
	var rules []string
	out := make(http.Header, len(h))
	for k, vals := range h {
		scrubbedVals := make([]string, len(vals))
		for i, v := range vals {
			line := k + ": " + v
			res := p.scrubber.Scrub(line)
			if !res.Clean {
				rules = appendUniqueRules(rules, findingsToRules(res.Findings))
				if _, after, ok := strings.Cut(res.Redacted, ": "); ok {
					scrubbedVals[i] = after
				} else {
					scrubbedVals[i] = res.Redacted
				}
			} else {
				scrubbedVals[i] = v
			}
		}
		out[k] = scrubbedVals
	}
	return rules, out
}

func findingsToRules(findings []Finding) []string {
	if len(findings) == 0 {
		return nil
	}
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Rule)
	}
	return out
}

func appendUniqueRules(dst, add []string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, r := range dst {
		seen[r] = struct{}{}
	}
	for _, r := range add {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		dst = append(dst, r)
	}
	return dst
}

func normalizeHost(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}
	if parsedHost, _, err := net.SplitHostPort(h); err == nil {
		h = parsedHost
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	return h
}

func splitHostPortDefault(addr, defaultPort string) (string, string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return addr, defaultPort
}
