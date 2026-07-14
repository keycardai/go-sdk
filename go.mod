module github.com/keycardai/go-sdk

go 1.23.0

require (
	github.com/cedar-policy/cedar-go v1.5.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/gowebpki/jcs v1.0.1
	golang.org/x/sync v0.11.0
)

require golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e // indirect

retract v0.14.0 // reverted: unfinished policy bundle package
