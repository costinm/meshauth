package meshauth

import "net/http"

var (
	Debug = false

	// Client used for local node ( MDS, etc) - not encrypted
	LocalHttpClient *http.Client
)
