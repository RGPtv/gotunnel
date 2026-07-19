package tunnel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/RGPtv/gotunnel/internal/mux"
)

func TestGetEndpointKeyHonorsConfiguredDomain(t *testing.T) {
	s := &Server{
		domain: "tunnel.example",
		tunnelMeta: map[string]TunnelMeta{
			"app": {},
		},
	}

	if got := s.getEndpointKey("APP.TUNNEL.EXAMPLE"); got != "app" {
		t.Fatalf("case-insensitive subdomain route = %q, want app", got)
	}
	if got := s.getEndpointKey("app.attacker.example"); got != "(default)" {
		t.Fatalf("unrelated host route = %q, want (default)", got)
	}
}

func TestValidateServerConfigRequiresCertificatePair(t *testing.T) {
	err := validateServerConfig(&ServerConfig{Token: "token", CertFile: "server.crt"})
	if err == nil {
		t.Fatal("certificate without key was accepted")
	}
	if err := validateServerConfig(&ServerConfig{Token: "token", CertFile: "server.crt", KeyFile: "server.key"}); err != nil {
		t.Fatalf("certificate pair rejected: %v", err)
	}
}

func TestUpdateTokenInConfigRestrictsPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not report POSIX permission bits")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(config, []byte("serverConfig:\n  token: old\n"), 0644); err != nil {
		t.Fatal(err)
	}

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalWD) })

	if err := UpdateTokenInConfig("new"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got&0077 != 0 {
		t.Fatalf("config permissions = %04o, want owner-only", got)
	}
}

func TestAIModeCORSDoesNotAllowCredentialedOriginReflection(t *testing.T) {
	s := &Server{
		tunnelMeta: map[string]TunnelMeta{
			"(default)": {AIMode: true, Session: &mux.Session{}},
		},
	}
	req := httptest.NewRequest(http.MethodOptions, "http://tunnel.test/", nil)
	req.Header.Set("Origin", "https://attacker.test")
	rr := httptest.NewRecorder()

	s.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("unexpected credentialed CORS header %q", got)
	}
}
