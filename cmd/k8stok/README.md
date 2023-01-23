Simple tool to get tokens from K8S and GKE.

By default it returns a JWT issued by K8S with audience "istio-ca", suitable to use with Istiod for debug.

The audience can be customized using "-aud AUDIENCE" - typically should be the base URL of the service where the token is used.

Using "-fed" returns a federated token - i.e. a JWT signed by Google, authenticating the K8S SA directly.

Using "-gsa GSA" will return a JWT token for the GSA. "default" will use the ASM data plane service account.
