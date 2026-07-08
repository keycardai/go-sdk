// Package main demonstrates multi-zone support: one server that verifies and exchanges
// tokens for several Keycard zones, routing each request by the token's issuer.
//
// Configure in Keycard before running:
//   - Two zones, each with a confidential client:
//     KEYCARD_ZONE_A_URL / KEYCARD_ZONE_A_CLIENT_ID / KEYCARD_ZONE_A_CLIENT_SECRET
//     KEYCARD_ZONE_B_URL / KEYCARD_ZONE_B_CLIENT_ID / KEYCARD_ZONE_B_CLIENT_SECRET
//   - A downstream resource to exchange for (KEYCARD_RESOURCE).
//
// Run:
//
//	KEYCARD_ZONE_A_URL=... KEYCARD_ZONE_B_URL=... KEYCARD_RESOURCE=... \
//	KEYCARD_ZONE_A_CLIENT_ID=... KEYCARD_ZONE_A_CLIENT_SECRET=... \
//	KEYCARD_ZONE_B_CLIENT_ID=... KEYCARD_ZONE_B_CLIENT_SECRET=... go run ./examples/multi-zone
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/keycardai/go-sdk/mcp"
)

func main() {
	aURL := os.Getenv("KEYCARD_ZONE_A_URL")
	bURL := os.Getenv("KEYCARD_ZONE_B_URL")
	resource := os.Getenv("KEYCARD_RESOURCE")
	if aURL == "" || bURL == "" || resource == "" {
		log.Fatal("KEYCARD_ZONE_A_URL, KEYCARD_ZONE_B_URL, and KEYCARD_RESOURCE are required")
	}

	// One credential carrying both zones' client credentials, keyed by zone URL. It is
	// self-describing: holding more than one zone makes the provider multi-zone.
	credential, err := mcp.NewMultiZoneClientSecret(map[string]mcp.ClientAuth{
		aURL: {ClientID: os.Getenv("KEYCARD_ZONE_A_CLIENT_ID"), ClientSecret: os.Getenv("KEYCARD_ZONE_A_CLIENT_SECRET")},
		bURL: {ClientID: os.Getenv("KEYCARD_ZONE_B_CLIENT_ID"), ClientSecret: os.Getenv("KEYCARD_ZONE_B_CLIENT_SECRET")},
	})
	if err != nil {
		log.Fatal(err)
	}

	// The verifier trusts tokens from either zone; the token's iss selects the zone and
	// its JWKS. A token from any other issuer is rejected.
	verifier, err := mcp.NewMultiZoneTokenVerifier([]string{aURL, bURL})
	if err != nil {
		log.Fatal(err)
	}

	provider, err := mcp.NewAuthProvider(mcp.WithApplicationCredential(credential))
	if err != nil {
		log.Fatal(err)
	}

	// Grant routes the exchange to whichever zone minted the request's token.
	handler := mcp.RequireBearerAuth(verifier)(
		provider.Grant([]string{resource})(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				info := mcp.AuthInfoFromRequest(r)
				ac := mcp.AccessContextFromRequest(r)
				token, err := ac.Access(resource)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"zone":  info.Issuer,
					"token": token.AccessToken,
				})
			}),
		),
	)

	mux := http.NewServeMux()
	mux.Handle("GET /api/resource", handler)

	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	log.Printf("Multi-zone server listening on %s (zones: %s, %s)", addr, aURL, bURL)
	log.Fatal(http.ListenAndServe(addr, mux))
}
