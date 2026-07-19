package setup

import "testing"

func TestValidateSetupRequestRejectsWildcardWithoutHTTPS(t *testing.T) {
	req := &setupRequest{
		Username:      "admin",
		Password:      "password",
		Domain:        "example.test",
		Wildcard:      true,
		DashboardPort: 4040,
	}
	if err := validateSetupRequest(req); err == nil {
		t.Fatal("wildcard configuration without HTTPS was accepted")
	}
}
