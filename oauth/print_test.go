package oauth

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestPrintLeavesOutSecrets checks every way a caller can print ClientAuthentication
// and DeviceAuthorization: each fmt verb, and slog with the text and JSON handlers.
// Each case lists the secret values, which no output may contain.
func TestPrintLeavesOutSecrets(t *testing.T) {
	basic := http.Header{}
	setBasicAuth(basic, "client-id", "client-secret")

	tests := []struct {
		name     string
		value    any
		secrets  []string
		wantV    string // %v, %+v, and %s
		wantGo   string // %#v
		wantText string // slog.TextHandler
		wantJSON string // slog.JSONHandler
	}{
		{
			name:     "client secret",
			value:    &ClientAuthentication{Header: basic, Form: url.Values{}},
			secrets:  []string{basic.Get("Authorization"), "client-secret"},
			wantV:    "{Header:[Authorization] Form:[]}",
			wantGo:   `oauth.ClientAuthentication{Header:[]string{"Authorization"}, Form:[]string{}}`,
			wantText: "v.header=[Authorization] v.form=[]",
			wantJSON: `"v":{"header":["Authorization"],"form":[]}`,
		},
		{
			name: "client assertion",
			value: &ClientAuthentication{Form: url.Values{
				"client_assertion":      {"assertion-jwt"},
				"client_assertion_type": {clientAssertionTypeJWTBearer},
				"client_id":             {"client-id"},
			}},
			secrets:  []string{"assertion-jwt"},
			wantV:    "{Header:[] Form:[client_assertion client_assertion_type client_id]}",
			wantGo:   `oauth.ClientAuthentication{Header:[]string{}, Form:[]string{"client_assertion", "client_assertion_type", "client_id"}}`,
			wantText: `v.header=[] v.form="[client_assertion client_assertion_type client_id]"`,
			wantJSON: `"v":{"header":[],"form":["client_assertion","client_assertion_type","client_id"]}`,
		},
		{
			name: "device authorization",
			value: DeviceAuthorization{
				DeviceCode:              "device-code",
				UserCode:                "WDJB-MJHT",
				VerificationURI:         "https://zone.example.com/device",
				VerificationURIComplete: "https://zone.example.com/device?user_code=WDJB-MJHT",
				ExpiresIn:               600,
				Interval:                5,
				ExpiresAt:               time.Date(2026, 11, 19, 15, 0, 0, 0, time.UTC),
			},
			secrets: []string{"device-code"},
			wantV: "{UserCode:WDJB-MJHT VerificationURI:https://zone.example.com/device " +
				"VerificationURIComplete:https://zone.example.com/device?user_code=WDJB-MJHT " +
				"ExpiresIn:600 Interval:5 ExpiresAt:2026-11-19 15:00:00 +0000 UTC}",
			wantGo: `oauth.DeviceAuthorization{UserCode:"WDJB-MJHT", VerificationURI:"https://zone.example.com/device", ` +
				`VerificationURIComplete:"https://zone.example.com/device?user_code=WDJB-MJHT", ` +
				`ExpiresIn:600, Interval:5, ExpiresAt:time.Date(2026, time.November, 19, 15, 0, 0, 0, time.UTC)}`,
			wantText: "v.user_code=WDJB-MJHT v.verification_uri=https://zone.example.com/device " +
				`v.verification_uri_complete="https://zone.example.com/device?user_code=WDJB-MJHT" ` +
				"v.expires_in=600 v.interval=5 v.expires_at=2026-11-19T15:00:00.000Z",
			wantJSON: `"v":{"user_code":"WDJB-MJHT","verification_uri":"https://zone.example.com/device",` +
				`"verification_uri_complete":"https://zone.example.com/device?user_code=WDJB-MJHT",` +
				`"expires_in":600,"interval":5,"expires_at":"2026-11-19T15:00:00Z"}`,
		},
	}

	// dropTime leaves the timestamp out of slog output so the expected lines are fixed.
	dropTime := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var text, js bytes.Buffer
			slog.New(slog.NewTextHandler(&text, dropTime)).Info("m", "v", tt.value)
			slog.New(slog.NewJSONHandler(&js, dropTime)).Info("m", "v", tt.value)

			outputs := []struct{ format, got, want string }{
				{"%v", fmt.Sprintf("%v", tt.value), tt.wantV},
				{"%+v", fmt.Sprintf("%+v", tt.value), tt.wantV},
				{"%s", fmt.Sprintf("%s", tt.value), tt.wantV},
				{"%#v", fmt.Sprintf("%#v", tt.value), tt.wantGo},
				{"slog text", text.String(), "level=INFO msg=m " + tt.wantText + "\n"},
				{"slog JSON", js.String(), `{"level":"INFO","msg":"m",` + tt.wantJSON + "}\n"},
			}
			for _, o := range outputs {
				if o.got != o.want {
					t.Errorf("%s:\n got %s\nwant %s", o.format, o.got, o.want)
				}
				for _, s := range tt.secrets {
					if strings.Contains(o.got, s) {
						t.Errorf("%s output contains secret %q: %s", o.format, s, o.got)
					}
				}
			}
		})
	}
}
