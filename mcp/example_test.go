package mcp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/keycardai/go-sdk/mcp"
)

func ExampleNewResourceBinding() {
	binding, err := mcp.NewResourceBinding("https://zone.keycard.cloud",
		mcp.WithResourceIdentifier("https://api.example.com/mcp"))
	if err != nil {
		panic(err)
	}
	requireBearer, err := binding.BearerAuth()
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", requireBearer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("/.well-known/", binding.MetadataHandler())

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	fmt.Println(rec.Code)
	fmt.Println(rec.Header().Get("WWW-Authenticate"))
	// Output:
	// 401
	// Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"
}
