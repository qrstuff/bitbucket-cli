package secret

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/99designs/keyring"
	"gopkg.in/yaml.v3"
)



const (
	// EnvToken is the environment variable for runtime token injection.
	// When set, it bypasses the keyring entirely.
	EnvToken = "BKT_TOKEN"

	envCredentialsPath = "BKT_CREDENTIALS_PATH"
	envBackend         = "KEYRING_BACKEND"
	envTimeout         = "BKT_KEYRING_TIMEOUT"
)

const (
	keyringTimeoutHeadless    = 3 * time.Second
	keyringTimeoutInteractive = 60 * time.Second
)

// ErrKeyringTimeout indicates a keyring operation timed out.
var ErrKeyringTimeout = errors.New("keyring operation timed out")

// TokenFromEnv returns the value of BKT_TOKEN if set, or empty string.
func TokenFromEnv() string {
	return strings.TrimSpace(os.Getenv(EnvToken))
}

// IsHeadless returns true if the environment is likely unable to handle keyring
// unlock prompts without hanging.
//
// On Linux this specifically targets SSH sessions without X11/Wayland forwarding,
// and other environments without a display or D-Bus session (cron/containers).
// On macOS/Windows, DISPLAY/DBus heuristics don't apply, so we treat SSH and
// CI sessions as headless to fail fast.
func IsHeadless() bool {
	// SSH session without display forwarding - this is the main hang case
	isSSH := os.Getenv("SSH_TTY") != "" || os.Getenv("SSH_CLIENT") != "" || os.Getenv("SSH_CONNECTION") != ""
	if isSSH {
		// On non-Linux platforms DISPLAY/Wayland doesn't indicate GUI availability.
		if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
			return true
		}
		hasDisplay := os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
		return !hasDisplay
	}

	// On macOS and Windows, local terminals can show GUI prompts without DISPLAY/DBus.
	// Treat CI/non-interactive sessions as headless to fail fast.
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return envEnabled(os.Getenv("CI"))
	}

	hasDisplay := os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	hasDBus := os.Getenv("DBUS_SESSION_BUS_ADDRESS") != ""

	// No display AND no D-Bus session (container, cron, systemd service, etc.)
	// If D-Bus is available, keyring may work without GUI prompts.
	return !hasDisplay && !hasDBus
}

func keyringTimeout() time.Duration {
	if d, ok := parseTimeoutEnv(strings.TrimSpace(os.Getenv(envTimeout))); ok {
		return d
	}
	if IsHeadless() {
		return keyringTimeoutHeadless
	}
	return keyringTimeoutInteractive
}

func parseTimeoutEnv(raw string) (time.Duration, bool) {
	if raw == "" {
		return 0, false
	}

	// Accept both Go-style duration values (e.g. "60s", "2m") and plain seconds ("60").
	if d, err := time.ParseDuration(raw); err == nil {
		if d > 0 {
			return d, true
		}
		return 0, false
	}

	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}

func timeoutHint() string {
	return fmt.Sprintf("keyring prompt may need more time. Increase timeout via %s (e.g. 60s or 2m)", envTimeout)
}

// Store wraps access to the configured keyring backend.
type Store struct {
	kr keyring.Keyring
}

type openOptions struct {
	fileDir         string
}

// Option customises how the secret store is opened.
type Option func(*openOptions)

// WithCredentialsPath sets the file for the plaintext store.
func WithCredentialsPath(path string) Option {
	return func(o *openOptions) {
		if path != "" {
			o.fileDir = path
		}
	}
}

// Open initialises the plaintext file-based secret store by default.
func Open(opts ...Option) (*Store, error) {
	settings := openOptions{}

	if path := strings.TrimSpace(os.Getenv(envCredentialsPath)); path != "" {
		settings.fileDir = path
	}

	for _, opt := range opts {
		opt(&settings)
	}

	if settings.fileDir == "" {
		settings.fileDir = defaultCredentialsPath()
	}

	// Use the plaintext keyring by default as requested.
	// This avoids library-based keyring issues on headless servers.
	kr := &plaintextKeyring{path: settings.fileDir}
	return &Store{kr: kr}, nil
}



// Set writes a secret value.
func (s *Store) Set(key, value string) error {
	if s == nil || s.kr == nil {
		return errors.New("secret store not initialized")
	}

	return s.withTimeout(func() error {
		return s.kr.Set(keyring.Item{
			Key:   key,
			Data:  []byte(value),
			Label: fmt.Sprintf("bkt %s", key),
		})
	})
}

// Get retrieves a secret value.
func (s *Store) Get(key string) (string, error) {
	if s == nil || s.kr == nil {
		return "", errors.New("secret store not initialized")
	}

	var item keyring.Item
	err := s.withTimeout(func() error {
		var getErr error
		item, getErr = s.kr.Get(key)
		return getErr
	})
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return "", os.ErrNotExist
		}
		return "", err
	}

	return string(item.Data), nil
}

// Delete removes a stored secret.
func (s *Store) Delete(key string) error {
	if s == nil || s.kr == nil {
		return errors.New("secret store not initialized")
	}

	err := s.withTimeout(func() error {
		return s.kr.Remove(key)
	})
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return nil
	}
	return err
}

// withTimeout runs fn with a timeout to prevent keyring operations from hanging.
func (s *Store) withTimeout(fn func() error) error {
	ch := make(chan error, 1)
	go func() {
		ch <- fn()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), keyringTimeout())
	defer cancel()

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return fmt.Errorf("%w; %s", ErrKeyringTimeout, timeoutHint())
	}
}

// TokenKey returns the keyring identifier for a host token.
func TokenKey(hostKey string) string {
	return fmt.Sprintf("host/%s/token", hostKey)
}

// IsNoKeyringError reports whether the error indicates that no native keyring
// backend is available on the system.
func IsNoKeyringError(err error) bool {
	return false // plaintext always works if file is writable
}

func defaultCredentialsPath() string {
	if path := os.Getenv(envCredentialsPath); path != "" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	// Default to project-specific dir in home
	return filepath.Join(home, ".bkt", "credentials")
}

type plaintextKeyring struct {
	path string
	mu   sync.RWMutex
}

func (p *plaintextKeyring) Get(key string) (keyring.Item, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	data, err := os.ReadFile(p.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return keyring.Item{}, keyring.ErrKeyNotFound
		}
		return keyring.Item{}, err
	}

	var secrets map[string]string
	if err := yaml.Unmarshal(data, &secrets); err != nil {
		return keyring.Item{}, fmt.Errorf("decode credentials: %w", err)
	}

	val, ok := secrets[key]
	if !ok {
		return keyring.Item{}, keyring.ErrKeyNotFound
	}

	return keyring.Item{
		Key:  key,
		Data: []byte(val),
	}, nil
}

func (p *plaintextKeyring) Set(item keyring.Item) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(p.path), 0700); err != nil {
		return err
	}

	secrets := make(map[string]string)
	data, err := os.ReadFile(p.path)
	if err == nil {
		_ = yaml.Unmarshal(data, &secrets)
	}

	secrets[item.Key] = string(item.Data)
	data, err = yaml.Marshal(secrets)
	if err != nil {
		return err
	}

	return os.WriteFile(p.path, data, 0600)
}

func (p *plaintextKeyring) Remove(key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := os.ReadFile(p.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var secrets map[string]string
	if err := yaml.Unmarshal(data, &secrets); err != nil {
		return err
	}

	if _, ok := secrets[key]; !ok {
		return nil
	}

	delete(secrets, key)
	data, err = yaml.Marshal(secrets)
	if err != nil {
		return err
	}

	return os.WriteFile(p.path, data, 0600)
}

func (p *plaintextKeyring) GetMetadata(key string) (keyring.Metadata, error) {
	return keyring.Metadata{}, nil
}

func (p *plaintextKeyring) Keys() ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	data, err := os.ReadFile(p.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var secrets map[string]string
	if err := yaml.Unmarshal(data, &secrets); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func envEnabled(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
