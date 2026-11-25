module github.com/keycardai/go-sdk/spiffe

go 1.24.0

replace github.com/keycardai/go-sdk => ..

require (
	github.com/keycardai/go-sdk v0.34.1
	github.com/spiffe/go-spiffe/v2 v2.9.0
	google.golang.org/grpc v1.79.3
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
