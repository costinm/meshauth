package meshauth

import "os"

// Configurations for the mesh. Besides 'mesh identity' and authn/authz, dynamic config is a main feature of the
// mesh.
//
// - JSON files in a base directory - this is included in this package.
// - HTTP with mesh auth - TODO
// - Yaml files - require adding a yaml parser ( and dependency )
// - K8S or other plugins
// - XDS - plugin.


// FindConfig is a simple loader for a config file.
func FindConfig(base string, s string) []byte {

	basecfg := os.Getenv(base)
	if basecfg != "" {
		return []byte(basecfg)
	}

	fb, err := os.ReadFile("./" + base + s)
	if err == nil {
		return fb
	}

	fb, err = os.ReadFile("/" + base + "/" + base + s)
	if err == nil {
		return fb
	}

	// Also look in the .ssh directory - this is mainly for secrets.
	fb, err = os.ReadFile(os.Getenv("HOME") + "/.ssh/" + base + s)
	if err == nil {
		return fb
	}

	return nil
}

