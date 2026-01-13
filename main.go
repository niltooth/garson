package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var defaultUser = detectDefaultUser()

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	if lrw.status == 0 {
		lrw.status = http.StatusOK
	}
	n, err := lrw.ResponseWriter.Write(b)
	lrw.bytes += int64(n)
	return n, err
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &loggingResponseWriter{ResponseWriter: w}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start).Round(time.Millisecond)
		status := wrapped.status
		if status == 0 {
			status = http.StatusOK
		}

		log.Printf("[garson] %s %s %d %dB %v %s %s",
			r.Method,
			r.URL.RequestURI(),
			status,
			wrapped.bytes,
			duration,
			r.RemoteAddr,
			r.UserAgent(),
		)
	})
}

func authMiddleware(next http.Handler, user, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providedUser, providedPass, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(providedUser), []byte(user)) != 1 ||
			subtle.ConstantTimeCompare([]byte(providedPass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="garson"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func generatePassword() (string, error) {
	buf := make([]byte, 18) // 24 chars when base64 URL encoded
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func main() {
	port := flag.Int("port", 0, "optional port (0 picks a random available port)")
	dir := flag.String("dir", ".", "directory to serve")
	user := flag.String("user", defaultUser, "basic auth username")
	openBrowserFlag := flag.Bool("open-browser", true, "open browser after start when supported")
	openHost := flag.String("open-host", "lan", "host to use when opening: local, hostname, lan")
	maxRuntime := flag.Duration("max-runtime", time.Hour, "max runtime before automatic shutdown (0 disables)")
	tlsEnabled := flag.Bool("tls", true, "enable TLS with a cached self-signed cert")
	tlsCertFile := flag.String("tls-cert", "", "path to TLS certificate (overrides cached self-signed)")
	tlsKeyFile := flag.String("tls-key", "", "path to TLS private key (overrides cached self-signed)")
	configPathFlag := flag.String("config", "", "path to config file (default: XDG config)")
	flag.Parse()

	cfgPath := effectiveConfigPath(*configPathFlag)
	cfg, err := loadOrCreateConfig(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		log.Fatalf("resolve directory: %v", err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		log.Fatalf("open directory: %v", err)
	}
	if !info.IsDir() {
		log.Fatalf("path is not a directory: %s", absDir)
	}

	password, err := generatePassword()
	if err != nil {
		log.Fatalf("generate password: %v", err)
	}

	fileServer := http.FileServer(http.Dir(absDir))
	handler := loggingMiddleware(authMiddleware(fileServer, *user, password))

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("start listener: %v", err)
	}

	openURL := pickOpenURL(listener, *openHost)
	openURLWithAuth := withAuthURL(openURL, *user, password)
	if *tlsEnabled {
		openURL = ensureHTTPS(openURL)
		openURLWithAuth = ensureHTTPS(openURLWithAuth)
	}
	log.Printf("Auth -> user: %s password: %s", *user, password)
	proto := "http"
	if *tlsEnabled {
		proto = "https"
	}
	log.Printf("Serving %s at %s://%s (open: %s)", absDir, proto, listener.Addr(), openURL)

	server := &http.Server{Handler: handler}
	startMaxRuntimeTimer(server, *maxRuntime)

	if *openBrowserFlag {
		if canOpenBrowser() {
			if err := openBrowser(openURLWithAuth); err != nil {
				log.Printf("browser open failed: %v", err)
			}
		} else {
			log.Printf("browser open skipped (no GUI detected)")
		}
	}

	if *tlsEnabled {
		certDir := defaultCertDir()
		certFile := firstNonEmpty(*tlsCertFile, cfg.CertFile)
		keyFile := firstNonEmpty(*tlsKeyFile, cfg.KeyFile)

		if (certFile == "") != (keyFile == "") {
			log.Fatalf("both -tls-cert and -tls-key (or config cert_file/key_file) must be provided together")
		}

		if certFile == "" && keyFile == "" {
			hostnames := certHosts(openURL, listener)
			var err error
			certFile, keyFile, err = ensureSelfSignedCert(certDir, hostnames)
			if err != nil {
				log.Fatalf("tls setup failed: %v", err)
			}
		} else {
			if !fileExists(certFile) || !fileExists(keyFile) {
				log.Fatalf("provided cert or key file does not exist")
			}
		}

		if err := server.ServeTLS(listener, certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve tls: %v", err)
		}
	} else {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}
}

func localhostURL(listener net.Listener) string {
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Sprintf("http://%s", listener.Addr())
	}
	host := addr.IP.String()
	if host == "" || addr.IP.IsUnspecified() {
		host = "localhost"
	}
	return fmt.Sprintf("http://%s:%d", host, addr.Port)
}

func withAuthURL(rawURL, user, password string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

func pickOpenURL(listener net.Listener, mode string) string {
	switch strings.ToLower(mode) {
	case "hostname":
		if u := hostnameURL(listener); u != "" {
			return u
		}
	case "lan", "public":
		if u := lanURL(listener); u != "" {
			return u
		}
	}
	return localhostURL(listener)
}

func ensureHTTPS(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Scheme == "" || u.Scheme == "http" {
		u.Scheme = "https"
	}
	return u.String()
}

func hostnameURL(listener net.Listener) string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return ""
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return ""
	}
	if !hasUsableAddress(addrs) {
		return ""
	}
	return fmt.Sprintf("http://%s:%d", host, listenerPort(listener))
}

func lanURL(listener net.Listener) string {
	ip := defaultRouteIP()
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("http://%s:%d", ip, listenerPort(listener))
}

type Config struct {
	CertFile string
	KeyFile  string
}

func loadOrCreateConfig(path string) (Config, error) {
	var cfg Config
	if path == "" {
		return cfg, nil
	}

	if !fileExists(path) {
		if err := writeDefaultConfig(path); err != nil {
			return cfg, err
		}
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	cfg = parseConfig(data)
	return cfg, nil
}

func parseConfig(b []byte) Config {
	var cfg Config
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"`)
		switch key {
		case "cert_file":
			cfg.CertFile = val
		case "key_file":
			cfg.KeyFile = val
		}
	}
	return cfg
}

func writeDefaultConfig(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("make config dir: %w", err)
	}
	content := `# garson config
# Provide paths to your own TLS certificate and key to override the generated self-signed cert.
# Leave empty to let garson generate and cache a self-signed cert.

cert_file = ""
key_file = ""
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func effectiveConfigPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "garson", "config.toml")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".config", "garson", "config.toml")
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func certHosts(openURL string, listener net.Listener) []string {
	var hosts []string
	if u, err := url.Parse(openURL); err == nil && u.Hostname() != "" {
		hosts = append(hosts, u.Hostname())
	}
	if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
		if ipStr := tcp.IP.String(); ipStr != "" && ipStr != "<nil>" {
			hosts = append(hosts, ipStr)
		}
	}
	if hn, err := os.Hostname(); err == nil && hn != "" {
		hosts = append(hosts, hn)
	}
	hosts = append(hosts, "localhost", "127.0.0.1")
	return unique(hosts)
}

func ensureSelfSignedCert(dir string, hosts []string) (string, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("make cert dir: %w", err)
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	now := time.Now()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", "", fmt.Errorf("serial: %w", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "garson",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range unique(hosts) {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if h != "" {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("create cert: %w", err)
	}

	if err := writePEM(certFile, "CERTIFICATE", der, 0o600); err != nil {
		return "", "", err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := writePEM(keyFile, "RSA PRIVATE KEY", keyBytes, 0o600); err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func defaultCertDir() string {
	if v := os.Getenv("XDG_CACHE_HOME"); v != "" {
		return filepath.Join(v, "garson", "tls")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cache", "garson", "tls")
	}
	return filepath.Join(os.TempDir(), "garson", "tls")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func unique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func listenerPort(listener net.Listener) int {
	if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}

func hasUsableAddress(addrs []string) bool {
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if !ip.IsLoopback() && !ip.IsUnspecified() {
			return true
		}
	}
	return false
}

// defaultRouteIP returns the IPv4 address of the interface used for the default route.
// It does this by creating a UDP "connection" to a well-known address without sending packets.
func defaultRouteIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	ip4 := localAddr.IP.To4()
	if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsUnspecified() {
		return ""
	}
	return ip4.String()
}

func detectDefaultUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	if v := os.Getenv("USERNAME"); v != "" {
		return v
	}
	return "garson"
}

func startMaxRuntimeTimer(server *http.Server, d time.Duration) {
	if d <= 0 {
		return
	}
	go func() {
		timer := time.NewTimer(d)
		defer timer.Stop()
		<-timer.C
		log.Printf("Max runtime %v reached; shutting down", d)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
			if err := server.Close(); err != nil {
				log.Printf("force close failed: %v", err)
			}
		}
	}()
}

func canOpenBrowser() bool {
	if os.Getenv("CI") != "" {
		return false
	}

	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	case "linux":
		if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("WSL_DISTRO_NAME") != "" {
			return true
		}
		return false
	default:
		return false
	}
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return fmt.Errorf("unsupported OS for auto-open")
	}
	return cmd.Start()
}
