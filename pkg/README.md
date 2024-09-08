# Server implementation


## Code organization

The top level consists of dependency-free helpers to use as a light auth and bootstrap library.

The pkg/ and cmd/ include code to run as an extended metadata server, should not be used in other packages:

- authz - WIP minimal authz library based on istio and gateway
- dns - in-process dns server
- mdb - integration with K8S or other IP->metadata info.
- mdsd - metadata server
- oidc - using heavier libraries for OIDC auth
- stsd - an STS server implementation.