module github.com/keycardai/go-sdk

go 1.22

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	golang.org/x/sync v0.11.0
)

retract v0.14.0 // reverted: unfinished policy bundle package
