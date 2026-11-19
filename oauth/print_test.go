package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"testing"
	"time"

	"github.com/keycardai/go-sdk/internal/printed/printedtest"
)

// TestPrintLeavesOutSecrets builds each type that holds a secret the way a caller
// gets it, and checks its String output and that no fmt or slog form holds a secret.
// internal/printed checks the exact GoString and slog forms.
func TestPrintLeavesOutSecrets(t *testing.T) {
	const issuer = "https://zone.example.com"
	ctx := context.Background()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := NewPEMPrivateKeyring(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), issuer, "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	identifiable, err := keyring.Key(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	keyD := key.D.String()

	clientSecret, err := NewClientSecret("client-id", "client-secret")
	if err != nil {
		t.Fatal(err)
	}
	multiZone, err := NewMultiZoneClientSecret(map[string]ClientAuth{
		issuer:                       {ClientID: "id-a", ClientSecret: "secret-a"},
		"https://zone-b.example.com": {ClientID: "id-b", ClientSecret: "secret-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	basic, err := clientSecret.ClientAuthentication(ctx, issuer, issuer+"/token")
	if err != nil {
		t.Fatal(err)
	}

	webIdentity := NewWebIdentity(WithClientID("client-id"), WithStorageDir(t.TempDir()), WithAudienceConfig("https://aud.example.com"))
	if err := webIdentity.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	workload, err := NewWorkloadIdentity(IdentityTokenFunc(func(context.Context) (string, error) { return "platform-token", nil }),
		WithWorkloadClientID("client-id"))
	if err != nil {
		t.Fatal(err)
	}
	keyManager := NewPrivateKeyManager(NewFilePrivateKeyStorage(t.TempDir()), "kid-2")
	if err := keyManager.BootstrapIdentity(); err != nil {
		t.Fatal(err)
	}
	deviceClient, err := NewDeviceAuthorizationClient(issuer, WithDeviceCredential(clientSecret))
	if err != nil {
		t.Fatal(err)
	}

	token := &TokenResponse{
		AccessToken: "access-token", TokenType: "Bearer", ExpiresIn: 3600, RefreshToken: "refresh-token",
		IDToken: "id-token", Scope: []string{"openid"}, IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}
	accessContext := NewAccessContext()
	accessContext.SetToken("https://api-a.example.com", token)
	accessContext.SetResourceError("https://api-b.example.com", ErrorDetail{Message: "denied", Code: "access_denied"})

	tests := []struct {
		name    string
		value   any
		want    string
		secrets []string
	}{
		{
			name:    "ClientAuthentication with a client secret",
			value:   basic,
			want:    "{Header:[Authorization] Form:[]}",
			secrets: []string{basic.Header.Get("Authorization"), "client-secret"},
		},
		{
			name: "ClientAuthentication with an assertion",
			value: &ClientAuthentication{Form: url.Values{
				"client_assertion":      {"assertion-jwt"},
				"client_assertion_type": {clientAssertionTypeJWTBearer},
			}},
			want:    "{Header:[] Form:[client_assertion client_assertion_type]}",
			secrets: []string{"assertion-jwt"},
		},
		{
			name: "DeviceAuthorization",
			value: DeviceAuthorization{
				DeviceCode: "device-code", UserCode: "WDJB-MJHT", VerificationURI: issuer + "/device",
				ExpiresIn: 600, Interval: 5, ExpiresAt: time.Date(2026, 11, 19, 15, 0, 0, 0, time.UTC),
			},
			want: "{UserCode:WDJB-MJHT VerificationURI:https://zone.example.com/device VerificationURIComplete: " +
				"ExpiresIn:600 Interval:5 ExpiresAt:2026-11-19 15:00:00 +0000 UTC}",
			secrets: []string{"device-code"},
		},
		{
			name:    "TokenResponse",
			value:   token,
			want:    "{TokenType:Bearer ExpiresIn:3600 Scope:[openid] IssuedTokenType:urn:ietf:params:oauth:token-type:access_token UserID:}",
			secrets: []string{"access-token", "refresh-token", "id-token"},
		},
		{
			name: "TokenExchangeRequest",
			value: TokenExchangeRequest{
				GrantType: "urn:ietf:params:oauth:grant-type:token-exchange", Resource: "https://api.example.com",
				SubjectToken: "subject-token", SubjectTokenType: "access_token", ActorToken: "actor-token",
				ActorTokenType: "jwt", ClientAssertion: "assertion-jwt", ClientAssertionType: "jwt-bearer", ClientID: "client-id",
			},
			want: "{GrantType:urn:ietf:params:oauth:grant-type:token-exchange Resource:https://api.example.com Audience: Scope: " +
				"RequestedTokenType: SubjectTokenType:access_token ActorTokenType:jwt ClientAssertionType:jwt-bearer ClientID:client-id}",
			secrets: []string{"subject-token", "actor-token", "assertion-jwt"},
		},
		{
			name: "AuthorizationCodeExchangeRequest",
			value: AuthorizationCodeExchangeRequest{
				Code: "auth-code", CodeVerifier: "code-verifier", RedirectURI: "http://127.0.0.1:8765/callback",
				ClientID: "client-id", ClientSecret: "client-secret", Credential: clientSecret,
			},
			want:    "{RedirectURI:http://127.0.0.1:8765/callback ClientID:client-id Credential:*oauth.ClientSecretCredential Resource:}",
			secrets: []string{"auth-code", "code-verifier", "client-secret"},
		},
		{
			name:    "AuthenticateRequest",
			value:   AuthenticateRequest{ClientID: "client-id", Scopes: []string{"openid"}, ClientSecret: "client-secret"},
			want:    "{ClientID:client-id Scopes:[openid] RedirectURI: CallbackPort:0 CallbackTimeout:0s Credential:<nil> Resource:}",
			secrets: []string{"client-secret"},
		},
		{
			name:    "RefreshAuthorizationRequest",
			value:   RefreshAuthorizationRequest{RefreshToken: "refresh-token", ClientID: "client-id", ClientSecret: "client-secret"},
			want:    "{ClientID:client-id Credential:<nil> Resources:[] Scopes:[]}",
			secrets: []string{"refresh-token", "client-secret"},
		},
		{
			name: "RegistrationResponse",
			value: &RegistrationResponse{
				ClientID: "client-id", ClientSecret: "client-secret", RegistrationAccessToken: "registration-token",
				RegistrationClientURI: issuer + "/register/client-id",
				Raw:                   map[string]any{"client_id": "client-id", "client_secret": "client-secret"},
			},
			want: "{ClientID:client-id ClientIDIssuedAt:0 ClientSecretExpiresAt:0 " +
				"RegistrationClientURI:https://zone.example.com/register/client-id Raw:[client_id client_secret]}",
			secrets: []string{"client-secret", "registration-token"},
		},
		{
			name:    "PKCEPair",
			value:   PKCEPair{CodeVerifier: "code-verifier", CodeChallenge: "code-challenge", CodeChallengeMethod: "S256"},
			want:    "{CodeChallenge:code-challenge CodeChallengeMethod:S256}",
			secrets: []string{"code-verifier"},
		},
		{
			name:    "ClientAuth",
			value:   ClientAuth{ClientID: "client-id", ClientSecret: "client-secret"},
			want:    "{ClientID:client-id}",
			secrets: []string{"client-secret"},
		},
		{
			name:    "single-zone ClientSecretCredential",
			value:   clientSecret,
			want:    "{ClientID:client-id Issuers:[]}",
			secrets: []string{"client-secret"},
		},
		{
			name:    "multi-zone ClientSecretCredential",
			value:   multiZone,
			want:    "{ClientID: Issuers:[https://zone-b.example.com https://zone.example.com]}",
			secrets: []string{"secret-a", "secret-b"},
		},
		{
			name:    "WebIdentityCredential",
			value:   webIdentity,
			want:    "{ClientID:client-id AudienceConfig:https://aud.example.com}",
			secrets: []string{webIdentity.keyManager.privateKey.D.String()},
		},
		{
			name:    "WorkloadIdentityCredential",
			value:   workload,
			want:    "{ClientID:client-id Source:oauth.IdentityTokenFunc}",
			secrets: []string{"platform-token"},
		},
		{
			name:    "TokenExchangeClient",
			value:   NewTokenExchangeClient(issuer, WithClientCredentials("client-id", "client-secret")),
			want:    "{Issuer:https://zone.example.com ClientID:client-id}",
			secrets: []string{"client-secret"},
		},
		{
			name:    "ClientCredentialsClient",
			value:   NewClientCredentialsClient(issuer, WithCCBasicAuth("client-id", "client-secret")),
			want:    "{Issuer:https://zone.example.com ClientID:client-id}",
			secrets: []string{"client-secret"},
		},
		{
			name:    "DeviceAuthorizationClient",
			value:   deviceClient,
			want:    "{Issuer:https://zone.example.com ClientID: Credential:*oauth.ClientSecretCredential}",
			secrets: []string{"client-secret"},
		},
		{
			name:    "AccessContext",
			value:   accessContext,
			want:    "{Resources:[https://api-a.example.com] ResourceErrors:map[https://api-b.example.com:{denied access_denied  }] GlobalError:<nil>}",
			secrets: []string{"access-token", "refresh-token", "id-token"},
		},
		{
			name:    "PEMPrivateKeyring",
			value:   keyring,
			want:    "{Issuer:https://zone.example.com KID:kid-1}",
			secrets: []string{keyD},
		},
		{
			name:    "IdentifiableKey",
			value:   identifiable,
			want:    "{Key:*rsa.PrivateKey Issuer:https://zone.example.com KID:kid-1}",
			secrets: []string{keyD},
		},
		{
			name:    "PrivateKeyManager",
			value:   keyManager,
			want:    "{KeyID:kid-2}",
			secrets: []string{keyManager.privateKey.D.String()},
		},
		{
			name:    "JWTSigner",
			value:   NewJWTSigner(keyring),
			want:    "{Keyring:*oauth.PEMPrivateKeyring}",
			secrets: []string{keyD},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			printedtest.Check(t, tt.value, tt.want, tt.secrets...)
		})
	}
}
