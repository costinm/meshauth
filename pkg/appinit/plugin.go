package appinit

import (
	"plugin"
)

// Use go build -buildmode=plugin.
// go-plugin is using grpc or net/rpc+yamux
func Load(name string) any {
	p, err := plugin.Open(name)
	if err != nil {
		return nil
	}
	p.Lookup("NewInstance")
	return p

}
