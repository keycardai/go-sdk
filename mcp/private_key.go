package mcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keycardai/go-sdk/oauth"
)

// PrivateKeyStorage persists RSA key pairs for WebIdentity.
type PrivateKeyStorage interface {
	Exists(keyID string) (bool, error)
	StoreKeyPair(keyID, privateKeyPEM string, publicKeyJWK map[string]any) error
	LoadKeyPair(keyID string) (privateKeyPEM string, publicKeyJWK map[string]any, err error)
	DeleteKeyPair(keyID string) (bool, error)
	ListKeyIDs() ([]string, error)
}

// FilePrivateKeyStorage implements PrivateKeyStorage using the filesystem.
type FilePrivateKeyStorage struct {
	storageDir string
}

// NewFilePrivateKeyStorage creates a new FilePrivateKeyStorage at the given directory.
func NewFilePrivateKeyStorage(dir string) *FilePrivateKeyStorage {
	return &FilePrivateKeyStorage{storageDir: dir}
}

func (s *FilePrivateKeyStorage) keyPath(keyID string) string {
	return filepath.Join(s.storageDir, keyID+".pem")
}

func (s *FilePrivateKeyStorage) metadataPath(keyID string) string {
	return filepath.Join(s.storageDir, keyID+".json")
}

// Exists returns true if both the PEM key and metadata files exist.
func (s *FilePrivateKeyStorage) Exists(keyID string) (bool, error) {
	if _, err := os.Stat(s.keyPath(keyID)); err != nil {
		return false, nil
	}
	if _, err := os.Stat(s.metadataPath(keyID)); err != nil {
		return false, nil
	}
	return true, nil
}

// StoreKeyPair stores a PEM private key and JWK metadata to disk.
func (s *FilePrivateKeyStorage) StoreKeyPair(keyID, privateKeyPEM string, publicKeyJWK map[string]any) error {
	if err := os.MkdirAll(s.storageDir, 0o755); err != nil {
		return fmt.Errorf("creating storage directory: %w", err)
	}

	metadata := map[string]any{
		"key_id":         keyID,
		"public_key_jwk": publicKeyJWK,
		"created_at":     float64(time.Now().Unix()),
		"algorithm":      "RS256",
	}

	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	if err := os.WriteFile(s.keyPath(keyID), []byte(privateKeyPEM), 0o600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}
	if err := os.WriteFile(s.metadataPath(keyID), metadataBytes, 0o644); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}

	return nil
}

// LoadKeyPair loads a PEM private key and JWK metadata from disk.
func (s *FilePrivateKeyStorage) LoadKeyPair(keyID string) (string, map[string]any, error) {
	pemData, err := os.ReadFile(s.keyPath(keyID))
	if err != nil {
		return "", nil, fmt.Errorf("reading private key: %w", err)
	}

	metadataBytes, err := os.ReadFile(s.metadataPath(keyID))
	if err != nil {
		return "", nil, fmt.Errorf("reading metadata: %w", err)
	}

	var metadata map[string]any
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return "", nil, fmt.Errorf("decoding metadata: %w", err)
	}

	publicKeyJWK, _ := metadata["public_key_jwk"].(map[string]any)
	return string(pemData), publicKeyJWK, nil
}

// DeleteKeyPair removes the PEM key and metadata files.
func (s *FilePrivateKeyStorage) DeleteKeyPair(keyID string) (bool, error) {
	deleted := false
	if err := os.Remove(s.keyPath(keyID)); err == nil {
		deleted = true
	}
	if err := os.Remove(s.metadataPath(keyID)); err == nil {
		deleted = true
	}
	return deleted, nil
}

// ListKeyIDs returns all key IDs stored in the directory.
func (s *FilePrivateKeyStorage) ListKeyIDs() ([]string, error) {
	entries, err := os.ReadDir(s.storageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var keyIDs []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".json") {
			keyID := strings.TrimSuffix(name, ".json")
			exists, _ := s.Exists(keyID)
			if exists {
				keyIDs = append(keyIDs, keyID)
			}
		}
	}
	return keyIDs, nil
}

// PrivateKeyManager generates and manages RSA key pairs for client assertions.
type PrivateKeyManager struct {
	storage    PrivateKeyStorage
	keyID      string
	privateKey *rsa.PrivateKey
	publicJWK  map[string]any
}

// NewPrivateKeyManager creates a new PrivateKeyManager.
func NewPrivateKeyManager(storage PrivateKeyStorage, keyID string) *PrivateKeyManager {
	return &PrivateKeyManager{
		storage: storage,
		keyID:   keyID,
	}
}

// BootstrapIdentity loads an existing key pair or generates a new one.
func (m *PrivateKeyManager) BootstrapIdentity() error {
	exists, err := m.storage.Exists(m.keyID)
	if err != nil {
		return fmt.Errorf("checking key existence: %w", err)
	}

	if exists {
		pemStr, jwk, err := m.storage.LoadKeyPair(m.keyID)
		if err != nil {
			return fmt.Errorf("loading key pair: %w", err)
		}
		key, err := parsePEMPrivateKey(pemStr)
		if err != nil {
			return fmt.Errorf("parsing private key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("expected RSA private key, got %T", key)
		}
		m.privateKey = rsaKey
		m.publicJWK = jwk
	} else {
		if err := m.generateAndStoreKeyPair(); err != nil {
			return fmt.Errorf("generating key pair: %w", err)
		}
	}

	return nil
}

// CreateClientAssertion creates a signed JWT for client authentication (RFC 7523).
func (m *PrivateKeyManager) CreateClientAssertion(ctx context.Context, issuer, audience string) (string, error) {
	if m.privateKey == nil {
		return "", fmt.Errorf("identity not bootstrapped; call BootstrapIdentity() first")
	}

	keyring := &staticPrivateKeyring{
		key:    m.privateKey,
		kid:    m.keyID,
		issuer: issuer,
	}

	signer := oauth.NewJWTSigner(keyring)

	now := time.Now().Unix()
	return signer.Sign(ctx, oauth.JWTClaims{
		Issuer:   issuer,
		Subject:  issuer,
		Audience: []string{audience},
		JWTID:    generateUUID(),
		IssuedAt: now,
		Expiry:   now + 300, // 5 minutes
	})
}

// PublicJWKS returns the public key in JWKS format.
func (m *PrivateKeyManager) PublicJWKS() map[string]any {
	if m.publicJWK == nil {
		return nil
	}
	return map[string]any{
		"keys": []any{m.publicJWK},
	}
}

// ClientID returns the key ID, which is used as the client ID.
func (m *PrivateKeyManager) ClientID() string {
	return m.keyID
}

// ClientJWKSURL returns the well-known JWKS URL for the given resource server URL.
func (m *PrivateKeyManager) ClientJWKSURL(resourceServerURL string) string {
	// Extract scheme + host from the URL
	idx := strings.Index(resourceServerURL, "://")
	if idx == -1 {
		return resourceServerURL + "/.well-known/jwks.json"
	}
	rest := resourceServerURL[idx+3:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx != -1 {
		rest = rest[:slashIdx]
	}
	return resourceServerURL[:idx+3] + rest + "/.well-known/jwks.json"
}

func (m *PrivateKeyManager) generateAndStoreKeyPair() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating RSA key: %w", err)
	}

	// Encode private key to PEM
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	privateKeyPEM := string(pem.EncodeToMemory(pemBlock))

	// Build public key JWK
	publicJWK := map[string]any{
		"kty": "RSA",
		"n":   oauth.Base64URLEncode(privateKey.PublicKey.N.Bytes()),
		"e":   oauth.Base64URLEncode(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		"kid": m.keyID,
		"alg": "RS256",
		"use": "sig",
	}

	if err := m.storage.StoreKeyPair(m.keyID, privateKeyPEM, publicJWK); err != nil {
		return err
	}

	m.privateKey = privateKey
	m.publicJWK = publicJWK
	return nil
}

func parsePEMPrivateKey(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if rsaErr != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return rsaKey, nil
	}
	return key, nil
}

// staticPrivateKeyring implements oauth.PrivateKeyring with a fixed key.
type staticPrivateKeyring struct {
	key    *rsa.PrivateKey
	kid    string
	issuer string
}

func (r *staticPrivateKeyring) Key(_ context.Context, _ string) (oauth.IdentifiableKey, error) {
	return oauth.IdentifiableKey{Key: r.key, Issuer: r.issuer, KID: r.kid}, nil
}

// generateUUID generates a random UUID v4 string.
func generateUUID() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant 1
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
