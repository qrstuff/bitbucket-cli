package secret

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/99designs/keyring"
)

func TestParseTimeoutEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want time.Duration
		ok   bool
	}{
		{name: "empty", raw: "", want: 0, ok: false},
		{name: "duration_seconds", raw: "60s", want: 60 * time.Second, ok: true},
		{name: "duration_minutes", raw: "2m", want: 2 * time.Minute, ok: true},
		{name: "plain_seconds", raw: "60", want: 60 * time.Second, ok: true},
		{name: "zero", raw: "0", want: 0, ok: false},
		{name: "negative", raw: "-1", want: 0, ok: false},
		{name: "garbage", raw: "nope", want: 0, ok: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseTimeoutEnv(tt.raw)
			if ok != tt.ok {
				t.Fatalf("ok=%v want %v (got=%v)", ok, tt.ok, got)
			}
			if ok && got != tt.want {
				t.Fatalf("got=%v want %v", got, tt.want)
			}
		})
	}
}

func TestKeyringTimeout_EnvOverride(t *testing.T) {
	t.Setenv("BKT_KEYRING_TIMEOUT", "2m")
	if got := keyringTimeout(); got != 2*time.Minute {
		t.Fatalf("got=%v want %v", got, 2*time.Minute)
	}
}

func TestTokenFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{name: "unset", env: "", want: ""},
		{name: "set", env: "my-token", want: "my-token"},
		{name: "trimmed", env: "  spaced-token  ", want: "spaced-token"},
		{name: "whitespace_only", env: "   ", want: ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvToken, tt.env)
			if got := TokenFromEnv(); got != tt.want {
				t.Fatalf("got=%q want %q", got, tt.want)
			}
		})
	}
}

func TestPlaintextKeyring(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "credentials.yml")
	kr := &plaintextKeyring{path: tempFile}

	// Test Set
	err := kr.Set(keyring.Item{Key: "test-key", Data: []byte("test-value")})
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Test Get
	item, err := kr.Get("test-key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(item.Data) != "test-value" {
		t.Fatalf("got %s, want %s", string(item.Data), "test-value")
	}

	// Test Keys
	keys, err := kr.Keys()
	if err != nil {
		t.Fatalf("Keys failed: %v", err)
	}
	if len(keys) != 1 || keys[0] != "test-key" {
		t.Fatalf("unexpected keys: %v", keys)
	}

	// Test Remove
	err = kr.Remove("test-key")
	if err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	_, err = kr.Get("test-key")
	if !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestStore_DefaultPath(t *testing.T) {
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".bkt", "credentials")
	if got := defaultCredentialsPath(); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}

	t.Setenv(envCredentialsPath, "/tmp/special-creds")
	if got := defaultCredentialsPath(); got != "/tmp/special-creds" {
		t.Fatalf("got %s, want %s", got, "/tmp/special-creds")
	}
}
