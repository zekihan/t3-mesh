package enroll

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTokenListAndRevoke(t *testing.T) {
	clock := time.Now()
	tokens := NewTokens(func() time.Time { return clock })

	agent, _, err := tokens.Create("agent-a")
	if err != nil {
		t.Fatal(err)
	}

	device, _, err := tokens.Create("device-phone-mesh")
	if err != nil {
		t.Fatal(err)
	}

	for i, token := range []string{agent, device} {
		hash := sha256.Sum256([]byte(token))
		entry := tokens.byHash[hash]
		entry.id = fmt.Sprintf("12345678%x%023x", i, i)
		tokens.byHash[hash] = entry
	}

	admin := Admin{Tokens: tokens}

	list := admin.execute(&adminRequest{Op: opTokens}).Tokens
	if len(list) != 2 || list[0].ID != "123456780" || list[1].ID != "123456781" ||
		list[0].Kind != KindAgent || list[1].Kind != KindDevice {
		t.Fatalf("token list = %+v", list)
	}

	checkTokenListPrivacy(t, list, agent, device)

	err = tokens.Revoke("12345678")
	if !errors.Is(err, errAmbiguousToken) {
		t.Fatalf("ambiguous revoke: %v", err)
	}

	err = tokens.Revoke(list[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tokens.Redeem(agent)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("redeemed a revoked token: %v", err)
	}

	clock = clock.Add(TokenTTL)

	if tokens.Outstanding() || len(tokens.List()) != 0 {
		t.Fatal("list contains an expired token")
	}
}

func checkTokenListPrivacy(t *testing.T, list []TokenInfo, tokens ...string) {
	t.Helper()

	payload, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}

	for _, token := range tokens {
		hash := sha256.Sum256([]byte(token))
		if strings.Contains(string(payload), token) ||
			strings.Contains(string(payload), hex.EncodeToString(hash[:])) {
			t.Fatal("list contains secret token material")
		}
	}
}
