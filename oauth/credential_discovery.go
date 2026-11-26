package oauth

import (
	"os"
	"slices"
	"strings"
)

const (
	credentialTypeEnv      = "KEYCARD_APPLICATION_CREDENTIAL_TYPE"
	clientIDEnv            = "KEYCARD_CLIENT_ID"
	clientSecretEnv        = "KEYCARD_CLIENT_SECRET"
	webIdentityStorageEnv  = "KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR"
	clientSecretType       = "client_secret"
	workloadIdentityType   = "workload_identity"
	webIdentityType        = "web_identity"
	legacyWorkloadIdentity = "eks_workload_identity"
)

// CredentialDiscoveryOption configures DiscoverCredential.
type CredentialDiscoveryOption func(*credentialDiscoveryConfig)

type credentialDiscoveryConfig struct {
	webIdentityServerName string
}

// WithWebIdentityServerName sets the server name used to derive a discovered
// WebIdentity credential's key ID. Other credential types ignore it.
func WithWebIdentityServerName(name string) CredentialDiscoveryOption {
	return func(cfg *credentialDiscoveryConfig) { cfg.webIdentityServerName = name }
}

// DiscoverCredential builds the application credential described by env. A nil
// map reads the process environment; a non-nil map, even if empty, replaces it.
// Empty values are unset. DiscoverCredential does not read KEYCARD_ZONE_URL.
//
// KEYCARD_CLIENT_ID and KEYCARD_CLIENT_SECRET configure a client secret.
// A token-file variable from NewFileTokenSource's discovery list configures a
// workload identity, with KEYCARD_CLIENT_ID attached if set.
// KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR configures a web identity.
//
// KEYCARD_APPLICATION_CREDENTIAL_TYPE selects client_secret, workload_identity
// (also accepted as the deprecated eks_workload_identity), or web_identity.
// An explicit web_identity selection can use NewWebIdentity's default storage.
//
// DiscoverCredential returns a CredentialDiscoveryError when the environment
// does not select one complete credential. Errors from the selected credential
// or its token source, such as WorkloadIdentityConfigurationError for a missing
// or empty token file, are returned unchanged.
func DiscoverCredential(env map[string]string, opts ...CredentialDiscoveryOption) (ApplicationCredential, error) {
	get := os.Getenv
	if env != nil {
		get = func(name string) string { return env[name] }
	}

	clientID, clientSecret := get(clientIDEnv), get(clientSecretEnv)
	storageDir := get(webIdentityStorageEnv)
	selected := get(credentialTypeEnv)
	var tokenPath string
	for _, name := range defaultFileTokenEnvVars {
		if tokenPath = get(name); tokenPath != "" {
			break
		}
	}

	var resolvable []string
	if clientID != "" && clientSecret != "" {
		resolvable = append(resolvable, clientSecretType)
	}
	if tokenPath != "" {
		resolvable = append(resolvable, workloadIdentityType)
	}
	if storageDir != "" {
		resolvable = append(resolvable, webIdentityType)
	}

	failure := func(reason CredentialDiscoveryReason, message string) (ApplicationCredential, error) {
		return nil, &CredentialDiscoveryError{Reason: reason, Resolvable: resolvable, Message: message}
	}
	if selected == legacyWorkloadIdentity {
		selected = workloadIdentityType
	}
	switch selected {
	case "":
		if clientSecret != "" && clientID == "" {
			return failure(CredentialDiscoveryIncomplete, clientSecretEnv+" is set without "+clientIDEnv)
		}
		switch len(resolvable) {
		case 0:
			return failure(CredentialDiscoveryAbsent, "no application credential configured; set "+
				clientIDEnv+" and "+clientSecretEnv+", a token file path in one of "+
				strings.Join(defaultFileTokenEnvVars, ", ")+", or "+webIdentityStorageEnv)
		case 1:
			selected = resolvable[0]
		default:
			return failure(CredentialDiscoveryAmbiguous, "the environment configures "+
				strings.Join(resolvable, ", ")+"; set "+credentialTypeEnv+" to choose one")
		}
	case clientSecretType, workloadIdentityType:
		if !slices.Contains(resolvable, selected) {
			needs := clientIDEnv + " and " + clientSecretEnv
			if selected == workloadIdentityType {
				needs = "a token file path in one of " + strings.Join(defaultFileTokenEnvVars, ", ")
			}
			return failure(CredentialDiscoveryNotSatisfiable, credentialTypeEnv+"="+selected+" requires "+needs)
		}
	case webIdentityType:
	default:
		return failure(CredentialDiscoveryUnknownType, "unknown "+credentialTypeEnv+"; use one of "+
			strings.Join([]string{clientSecretType, workloadIdentityType, webIdentityType}, ", "))
	}

	switch selected {
	case clientSecretType:
		credential, err := NewClientSecret(clientID, clientSecret)
		if err != nil {
			return nil, err
		}
		return credential, nil
	case workloadIdentityType:
		source, err := NewFileTokenSource(WithFileTokenPath(tokenPath))
		if err != nil {
			return nil, err
		}
		credential, err := NewWorkloadIdentity(source, WithWorkloadClientID(clientID))
		if err != nil {
			return nil, err
		}
		return credential, nil
	default:
		var cfg credentialDiscoveryConfig
		for _, opt := range opts {
			opt(&cfg)
		}
		return NewWebIdentity(WithStorageDir(storageDir), WithServerName(cfg.webIdentityServerName)), nil
	}
}
