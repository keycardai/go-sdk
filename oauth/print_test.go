package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keycardai/go-sdk/internal/printed"
	"github.com/keycardai/go-sdk/internal/printed/printedtest"
)

// Spec row 9 (client-secret): the client authentication result shows the header
// name Authorization and no header value or client secret.
// Spec row 38 (device-authorization): no printed form of a DeviceAuthorization
// holds the device_code, and every other field is shown.
// Spec row 27 (token-exchange): no printed form of a token-exchange request or a
// token response holds a token, and every other field is shown.
//
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
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("file-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	discoveredSecret, err := DiscoverCredential(map[string]string{
		"KEYCARD_CLIENT_ID": "client-id", "KEYCARD_CLIENT_SECRET": "discovered-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	discoveredWorkload, err := DiscoverCredential(map[string]string{
		"KEYCARD_CLIENT_ID": "client-id", "AWS_WEB_IDENTITY_TOKEN_FILE": tokenFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	actorClient := NewTokenExchangeClient(issuer, WithTokenExchangeCredential(clientSecret),
		WithTokenExchangeActor(IdentityTokenFunc(func(context.Context) (string, error) { return "actor-token", nil })))

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
			name: "IntrospectTokenRequest",
			value: IntrospectTokenRequest{
				Token: "introspection-token", TokenTypeHint: "access_token", Credential: discoveredSecret,
			},
			want:    "{TokenTypeHint:access_token Credential:*oauth.ClientSecretCredential}",
			secrets: []string{"introspection-token", "discovered-secret"},
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
			want:    "{Issuer:https://zone.example.com ClientID:client-id Credential:<nil> Actor:<nil>}",
			secrets: []string{"client-secret"},
		},
		{
			name:    "TokenExchangeClient with a credential and an actor token source",
			value:   actorClient,
			want:    "{Issuer:https://zone.example.com ClientID: Credential:*oauth.ClientSecretCredential Actor:oauth.IdentityTokenFunc}",
			secrets: []string{"client-secret", "actor-token"},
		},
		{
			name: "ClientCredentialsRequest",
			value: ClientCredentialsRequest{
				Resource: "https://api.example.com", Scope: "read", ClientAssertion: "assertion-jwt",
				ClientAssertionType: "jwt-bearer", ClientID: "client-id",
			},
			want:    "{Resource:https://api.example.com Scope:read ClientAssertionType:jwt-bearer ClientID:client-id}",
			secrets: []string{"assertion-jwt"},
		},
		{
			name: "ImpersonateRequest",
			value: ImpersonateRequest{
				UserIdentifier: "user-1", Resource: "https://api.example.com", Scopes: []string{"read"},
				ClientAssertion: "assertion-jwt", ClientAssertionType: "jwt-bearer",
			},
			want:    "{UserIdentifier:user-1 Resource:https://api.example.com Scopes:[read] ClientAssertionType:jwt-bearer}",
			secrets: []string{"assertion-jwt"},
		},
		{
			name: "RevokeTokenRequest",
			value: RevokeTokenRequest{
				Token: "refresh-token", TokenTypeHint: "refresh_token", ClientID: "client-id", ClientSecret: "client-secret",
			},
			want:    "{TokenTypeHint:refresh_token ClientID:client-id Credential:<nil>}",
			secrets: []string{"refresh-token", "client-secret"},
		},
		{
			name:    "discovered ClientSecretCredential",
			value:   discoveredSecret,
			want:    "{ClientID:client-id Issuers:[]}",
			secrets: []string{"discovered-secret"},
		},
		{
			name:    "discovered WorkloadIdentityCredential",
			value:   discoveredWorkload,
			want:    "{ClientID:client-id Source:*oauth.FileTokenSource}",
			secrets: []string{"file-token"},
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
			want:    "{Resources:[https://api-a.example.com] ResourceErrors:map[https://api-b.example.com:{denied access_denied  <nil> }] GlobalError:<nil>}",
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

// Spec row 38 (device-authorization): the JSON of a DeviceAuthorization has the
// device_code.
// Spec row 27 (token-exchange): the JSON of a token response has every token.
//
// TestJSONKeepsSecrets checks that encoding/json still writes the values that the
// printed forms leave out, so persisted tokens and device authorizations still work.
func TestJSONKeepsSecrets(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{
			name:  "TokenResponse",
			value: &TokenResponse{AccessToken: "access-token", TokenType: "Bearer", RefreshToken: "refresh-token", IDToken: "id-token"},
			want:  `{"access_token":"access-token","token_type":"Bearer","refresh_token":"refresh-token","id_token":"id-token"}`,
		},
		{
			name:  "DeviceAuthorization",
			value: DeviceAuthorization{DeviceCode: "device-code", UserCode: "U", VerificationURI: "https://zone.example.com/device"},
			want: `{"device_code":"device-code","user_code":"U","verification_uri":"https://zone.example.com/device",` +
				`"expires_in":0,"interval":0,"expires_at":"0001-01-01T00:00:00Z"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

// TestPrintedFormsListEveryField checks that every exported field of each type with
// a printed form is either printed or marked secret, so a new field cannot drop out
// of the printed form unnoticed.
func TestPrintedFormsListEveryField(t *testing.T) {
	entry := func(v interface{ printed() printed.Struct }, secret ...string) printedtest.Type {
		return printedtest.Type{Value: v, Form: v.printed(), Secret: secret}
	}
	printedtest.CheckFields(t, ".", []printedtest.Type{
		entry(NewAccessContext()),
		entry(AuthenticateRequest{}, "ClientSecret"),
		entry(AuthorizationCodeExchangeRequest{}, "Code", "CodeVerifier", "ClientSecret"),
		entry(ClientAuth{}, "ClientSecret"),
		entry(ClientAuthentication{}),
		entry(&ClientCredentialsClient{}),
		entry(ClientCredentialsRequest{}, "ClientAssertion"),
		entry(&ClientSecretCredential{}),
		entry(DeviceAuthorization{}, "DeviceCode"),
		entry(&DeviceAuthorizationClient{}),
		entry(IdentifiableKey{}),
		entry(ImpersonateRequest{}, "ClientAssertion"),
		entry(IntrospectTokenRequest{}, "Token"),
		entry(&JWTSigner{}),
		entry(&PEMPrivateKeyring{}),
		entry(PKCEPair{}, "CodeVerifier"),
		entry(&PrivateKeyManager{}),
		entry(RefreshAuthorizationRequest{}, "RefreshToken", "ClientSecret"),
		entry(RegistrationResponse{}, "ClientSecret", "RegistrationAccessToken"),
		entry(RevokeTokenRequest{}, "Token", "ClientSecret"),
		entry(&TokenExchangeClient{}),
		entry(TokenExchangeRequest{}, "SubjectToken", "ActorToken", "ClientAssertion"),
		entry(TokenResponse{}, "AccessToken", "RefreshToken", "IDToken"),
		entry(&WebIdentityCredential{}),
		entry(&WorkloadIdentityCredential{}),
	})
}
