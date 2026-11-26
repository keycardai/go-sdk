module github.com/keycardai/go-sdk/spiffe

go 1.25.0

replace github.com/keycardai/go-sdk => ..

require (
	github.com/keycardai/go-sdk v0.41.0
	github.com/spiffe/go-spiffe/v2 v2.9.0
	google.golang.org/grpc v1.83.2
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
