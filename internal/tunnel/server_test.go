package tunnel

import (
	"testing"
	"time"
)

func TestTCPPortAllowListHonorsConfiguredHost(t *testing.T) {
	s := &Server{allowedTCPPorts: []string{"127.0.0.1:2222"}}
	if !s.isTCPPortAllowed("127.0.0.1:2222") {
		t.Fatal("exact configured address was rejected")
	}
	if s.isTCPPortAllowed(":2222") {
		t.Fatal("host-specific rule permitted a public bind")
	}
}

func TestTCPPortAllowListAllowsPortOnlyRule(t *testing.T) {
	s := &Server{allowedTCPPorts: []string{":2222"}}
	if !s.isTCPPortAllowed(":2222") {
		t.Fatal("port-only rule was rejected")
	}
}

func TestAuthLimiterOnlyCountsFailures(t *testing.T) {
	b := &authBucket{lastSeen: time.Now()}
	for range authRateLimit + 1 {
		if !b.allow() {
			t.Fatal("successful attempts must not consume the failure budget")
		}
	}
	for range authRateLimit {
		b.recordFailure()
	}
	if b.allow() {
		t.Fatal("failure budget was not enforced")
	}
}
