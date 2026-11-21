package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAllowlistDomainWildcardAndIPRules(t *testing.T) {
	al := NewDomainAllowlist([]string{
		"api.anthropic.com",
		"*.pythonhosted.org",
		"10.0.0.5",
	})

	allowed := []string{
		"api.anthropic.com",
		"API.ANTHROPIC.COM:443",
		"files.pythonhosted.org",
		"a.b.pythonhosted.org",
		"10.0.0.5",
	}
	for _, h := range allowed {
		if !al.Allows(h) {
			t.Fatalf("expected Allows(%q) = true", h)
		}
	}

	denied := []string{
		"evil.example.com",
		"sub.api.anthropic.com",
		"evilpythonhosted.org",
		"pythonhosted.org",
		"169.254.169.254",
		"1.1.1.1",
		"",
	}
	for _, h := range denied {
		if al.Allows(h) {
			t.Fatalf("expected Allows(%q) = false", h)
		}
	}

	// Empty allowlist must default-deny everything.
	empty := NewDomainAllowlist(nil)
	if empty.Allows("api.anthropic.com") {
		t.Fatalf("empty allowlist must deny all domains")
	}
}

func TestHTTPProxyEnforcesAllowlistAndBlocksSecrets(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Upstream-Echo", r.Header.Get("X-Test"))
		_, _ = w.Write([]byte("echo:" + string(body)))
	}))
	t.Cleanup(upstream.Close)
	upstreamAddr := strings.TrimPrefix(upstream.URL, "http://")

	scrubber := NewScrubber(ScrubberConfig{
		AdditionalSecrets: []string{"env_secret_value_98765"},
	})

	ep, err := NewEgressProxy(ProxyConfig{
		AllowedDomains: []string{"allowed.example.com"},
		Scrubber:       scrubber,
		SecretAction:   SecretActionBlock,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
	})
	if err != nil {
		t.Fatalf("NewEgressProxy() error = %v", err)
	}
	if err := ep.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		_ = ep.Close(context.Background())
	})

	proxyURL, err := url.Parse(ep.HTTPURL())
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	// 1. Allowed domain + clean payload succeeds.
	req, _ := http.NewRequest(http.MethodPost, "http://allowed.example.com/v1/check", strings.NewReader("clean payload"))
	req.Header.Set("X-Test", "ok")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("clean HTTP request error = %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "echo:clean payload" {
		t.Fatalf("clean request got status %d body %q", resp.StatusCode, string(body))
	}

	// 2. Disallowed domain is blocked with 403 and never hits upstream.
	hitsBefore := upstreamHits.Load()
	resp, err = client.Get("http://exfil.evil.example/steal")
	if err != nil {
		t.Fatalf("blocked domain request error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disallowed domain status = %d, want 403", resp.StatusCode)
	}
	if upstreamHits.Load() != hitsBefore {
		t.Fatalf("disallowed domain contacted upstream!")
	}

	// 3. Allowed domain with secret in body is blocked with 403.
	resp, err = client.Post("http://allowed.example.com/upload", "text/plain",
		strings.NewReader("leaked key: sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"))
	if err != nil {
		t.Fatalf("secret body request error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("secret body status = %d, want 403", resp.StatusCode)
	}

	// 4. Allowed domain with known .env secret in query string is blocked with 403.
	resp, err = client.Get("http://allowed.example.com/ping?data=env_secret_value_98765")
	if err != nil {
		t.Fatalf("secret query request error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("secret query status = %d, want 403", resp.StatusCode)
	}
	if upstreamHits.Load() != hitsBefore {
		t.Fatalf("secret leak requests contacted upstream!")
	}

	stats := ep.Stats()
	if stats.AllowedCount != 1 || stats.BlockedDomainCount != 1 || stats.BlockedSecretCount != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestHTTPProxySecretActionRedactScrubsPayload(t *testing.T) {
	var receivedBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	upstreamAddr := strings.TrimPrefix(upstream.URL, "http://")

	ep, err := NewEgressProxy(ProxyConfig{
		AllowedDomains: []string{"allowed.example.com"},
		Scrubber:       NewScrubber(ScrubberConfig{}),
		SecretAction:   SecretActionRedact,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
	})
	if err != nil {
		t.Fatalf("NewEgressProxy() error = %v", err)
	}
	if err := ep.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = ep.Close(context.Background()) })

	proxyURL, _ := url.Parse(ep.HTTPURL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Post("http://allowed.example.com/log", "text/plain",
		strings.NewReader("aws=AKIAIOSFODNN7REALKEY"))
	if err != nil {
		t.Fatalf("redact POST error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redact POST status = %d, want 200", resp.StatusCode)
	}
	if receivedBody != "aws=[REDACTED:aws_access_key]" {
		t.Fatalf("upstream received %q, want redacted body", receivedBody)
	}
	if ep.Stats().RedactedCount != 1 {
		t.Fatalf("RedactedCount = %d, want 1", ep.Stats().RedactedCount)
	}
}

func TestHTTPConnectTunnelAllowlist(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = echoLn.Close() })
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	ep, err := NewEgressProxy(ProxyConfig{
		AllowedDomains: []string{"api.anthropic.com"},
		Scrubber:       NewScrubber(ScrubberConfig{}),
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, echoLn.Addr().String())
		},
	})
	if err != nil {
		t.Fatalf("NewEgressProxy() error = %v", err)
	}
	if err := ep.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = ep.Close(context.Background()) })

	// Allowed CONNECT succeeds and tunnels bidirectionally.
	conn, err := net.DialTimeout("tcp", ep.HTTPAddr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	_, _ = io.WriteString(conn, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		t.Fatalf("allowed CONNECT status = %q, err = %v", statusLine, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	_, _ = io.WriteString(conn, "ping-tunnel\n")
	echoed, err := br.ReadString('\n')
	if err != nil || echoed != "ping-tunnel\n" {
		t.Fatalf("tunnel echo = %q, err = %v", echoed, err)
	}

	// Disallowed CONNECT receives 403 Forbidden.
	conn2, err := net.DialTimeout("tcp", ep.HTTPAddr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy 2: %v", err)
	}
	defer conn2.Close()

	_, _ = io.WriteString(conn2, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
	statusLine2, err := bufio.NewReader(conn2).ReadString('\n')
	if err != nil || !strings.Contains(statusLine2, "403") {
		t.Fatalf("blocked CONNECT status = %q, err = %v; want 403", statusLine2, err)
	}
}

func TestSOCKS5ProxyAllowlistAndTunnel(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = echoLn.Close() })
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	ep, err := NewEgressProxy(ProxyConfig{
		AllowedDomains: []string{"pypi.org"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, echoLn.Addr().String())
		},
	})
	if err != nil {
		t.Fatalf("NewEgressProxy() error = %v", err)
	}
	if err := ep.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = ep.Close(context.Background()) })

	// 1. Allowed domain via SOCKS5 ATYP=DOMAIN.
	conn, rep := socks5ConnectDomain(t, ep.SOCKS5Addr(), "pypi.org", 443)
	defer conn.Close()
	if rep != socksRepSuccess {
		t.Fatalf("allowed SOCKS5 reply = 0x%02x, want 0x00", rep)
	}
	_, _ = io.WriteString(conn, "socks-ok\n")
	echoed, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || echoed != "socks-ok\n" {
		t.Fatalf("SOCKS5 echo = %q, err = %v", echoed, err)
	}

	// 2. Disallowed domain rejected with REP=0x02 (not allowed by ruleset).
	connDenied, repDenied := socks5ConnectDomain(t, ep.SOCKS5Addr(), "evil.example.com", 443)
	_ = connDenied.Close()
	if repDenied != socksRepNotAllowed {
		t.Fatalf("blocked SOCKS5 domain reply = 0x%02x, want 0x02", repDenied)
	}

	// 3. Raw IPv4 (cloud metadata SSRF) rejected with REP=0x02.
	connIP, repIP := socks5ConnectIPv4(t, ep.SOCKS5Addr(), net.IPv4(169, 254, 169, 254), 80)
	_ = connIP.Close()
	if repIP != socksRepNotAllowed {
		t.Fatalf("blocked SOCKS5 IPv4 reply = 0x%02x, want 0x02", repIP)
	}

	// Verify ProxyEnv emits expected proxy env variables.
	env := ep.ProxyEnv()
	if len(env) < 6 {
		t.Fatalf("ProxyEnv() = %v, expected HTTP_PROXY/HTTPS_PROXY/ALL_PROXY", env)
	}
}

func socks5ConnectDomain(t *testing.T, proxyAddr, domain string, port uint16) (net.Conn, byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	// Greeting: VER=5, NMETHODS=1, NO AUTH
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write socks5 greeting: %v", err)
	}
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetResp); err != nil || greetResp[0] != 0x05 || greetResp[1] != 0x00 {
		t.Fatalf("bad socks5 greeting reply: %v, err=%v", greetResp, err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	req = append(req, []byte(domain)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write socks5 connect: %v", err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatalf("read socks5 reply: %v", err)
	}
	return conn, rep[1]
}

func socks5ConnectIPv4(t *testing.T, proxyAddr string, ip net.IP, port uint16) (net.Conn, byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write socks5 greeting: %v", err)
	}
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetResp); err != nil {
		t.Fatalf("read socks5 greeting: %v", err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write socks5 ipv4 connect: %v", err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatalf("read socks5 reply: %v", err)
	}
	return conn, rep[1]
}
