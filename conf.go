package meshauth

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// TODO: Config should be associated with a context - along with telemetry (logs), auth.
// this allows easier testing and tenancy.

// TODO: map FOO_BAR to foo.bar, construct yaml equivalent
// Reload the files
// Dynamic Flags - https://github.com/mwitkow/go-flagz, fortio:

// Simple file-based config and secret store.
//
// Implements a Store interface with List/Get/Set interface.
//
// TODO: Watch interface - using messages/pubsub !!!
//
// TODO: switch to yaml, support K8S style
//
// TODO: integrate with krun, use the REST as a config source, possibly with watcher

// Conf impplements a ConfSource and is used for bootstrap info.
// It may be used for general configuration of the app as well.
type Conf struct {
	// Base directory. If not set, no config will be saved and read
	// will only return env or in-memory configs. First will be used for write.
	base []string

	// Flattened config - can be backed by env variables.
	// It is configured from Android side with the config (settings)
	// ssid, pass, vpn_ext.
	Conf map[string]string `json:"Conf,omitempty"`

	// additional stores. Key is the prefix for the name.
	//stores map[string]ugatesvc.Store

	m sync.RWMutex
	// if base is empty, this will be used to persist the configs.
	inMemory map[string][]byte

	// Additional/federated sources
	Sources []Store
}

// NewConf Returns a config store.
//
// Implements a basic auth.Store interface
// If base is not specified, the config will be empty and in-memory.
func NewConf(base ...string) *Conf {
	// TODO: https for remote - possibly using local creds and K8S style or XDS
	env := os.Environ()
	envconf := map[string]string{}
	for _, ev := range env {
		kv := strings.SplitN(ev, "=", 2)
		if len(kv) == 2 {
			envconf[kv[0]] = kv[1]
		}
	}
	return &Conf{
		base:     base,
		Conf:     envconf,
		inMemory: map[string][]byte{},
	}
}

func (c *Conf) List(name string, tp string) ([]string, error) {
	res := []string{}

	return res, nil
}

// Secrets - pem, acl
// From config dir, fallback to .ssh, .lego and /etc/certs
//
// "name" may be a hostname
func (c *Conf) Get(name string) ([]byte, error) {
	c.m.RLock()
	inmd := c.inMemory[name]
	c.m.RUnlock()
	if inmd != nil {
		return inmd, nil
	}

	envName := strings.ReplaceAll(name, ".", "_")
	envName = strings.ReplaceAll(envName, "/", "_")
	envd := os.Getenv(envName)
	if envd != "" {
		return []byte(envd), nil
	}

	for _, b := range c.base {
		l := filepath.Join(b, name)

		if _, err := os.Stat(l); err == nil { // || !os.IsNotExist(err)
			res, err := ioutil.ReadFile(l)
			if err == nil {
				return res, nil
			}
		}
		if _, err := os.Stat(l + ".json"); err == nil { // || !os.IsNotExist(err)
			res, err := ioutil.ReadFile(l + ".json")
			if err == nil {
				return res, nil
			}
		}
		if _, err := os.Stat(l + ".yaml"); err == nil { // || !os.IsNotExist(err)
			res, err := ioutil.ReadFile(l + ".yaml")
			if err == nil {
				return res, nil
			}
		}
	}

	// name may be a hostname - use it to load ACME certificate for the host.

	return nil, nil
}

func (c *Conf) Set(conf string, data []byte) error {
	if c == nil || c.base == nil || len(c.base) == 0 {
		// In memory
		c.m.Lock()
		c.inMemory[conf] = data
		c.m.Unlock()

		return nil
	}
	err := ioutil.WriteFile(c.base[0]+conf, data, 0700)
	if err != nil {
		log.Println("Error saving ", err, c.base, conf)
	}
	return err
}

// Helpers

func Get(h2 Store, name string, to interface{}) error {
	raw, err := h2.Get(name)
	if err != nil {
		log.Println("name:", err)
		raw = []byte("{}")
		//return nil
	}
	if len(raw) > 0 {
		// TODO: detect yaml or proto ?
		if err := json.Unmarshal(raw, to); err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

// ConfInt returns an string setting, with default value, from the Store.
func ConfStr(cs Store, name, def string) string {
	if cs == nil {
		return def
	}
	b, _ := cs.Get(name)
	if b == nil {
		return def
	}
	return string(b)
}

// ConfInt returns an int setting, with default value, from the Store.
func ConfInt(cs Store, name string, def int) int {
	if cs == nil {
		return def
	}
	b, _ := cs.Get(name)
	if b == nil {
		return def
	}
	v, err := strconv.Atoi(string(b))
	if err != nil {
		return def
	}
	return v
}
