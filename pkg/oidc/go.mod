module github.com/costinm/meshauth/pkg/oidc

go 1.21

replace github.com/costinm/meshauth => ../../

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/costinm/meshauth v0.0.0-20230606163944-0cc2116c135d
	gopkg.in/square/go-jose.v2 v2.6.0
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	golang.org/x/crypto v0.15.0 // indirect
	golang.org/x/net v0.18.0 // indirect
	golang.org/x/oauth2 v0.14.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
