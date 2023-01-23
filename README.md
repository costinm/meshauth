# Minimal mesh-focused auth library

This is an attempt to have a small, low-resource/WASM friendly library with no
external dependencies encapsulating the most common mesh auth and provisioning patterns.

The code is in large part based on/forked from Istio and few of my projects, to remove dependencies  and keep a minimal package for native mesh integration.

Provisioning and config are sometimes separated from auth - but it is safer and simpler
and treat both as part of the 'security' layer. This package will attempt to bootstrap 
config using environment-provided certificate and secrets and provides support 
for config updates using signed messages.


## Goals

- minimal code - only auth features commonly used in mesh with no external dependency
- minimal user config - auto-detect as much as possible from environment.
- clean and commented interactions with external systems
- support Spiffee, DNS and Matter IOT certificates

## Environment auto detection and configuration

A mesh application may be deployed in multiple environments and requires a number
of user-specific configs - trust domain, namespace, cluster names, etc. Setting it
manually adds complexity to the helm/install charts, and is easy to get wrong with
major negative impact. 


Istio automates this using injection - adding a number of volumes and environemnt 
variables. While some names are istio specific and not ideal, it is a good starting
point and can be gradually improved.

Istio has evolved and has to maintain backward compat - a lot of the env variables
are duplicated, redundant or not really needed in all cases. 

The current 'best practice' is to rely on a platform or CSI provider for client  
certificates. In the absence of it, the app can authenticate using JWTs - it is possible
to get them from TokenRequest (giving each service account permission to get tokens
for itself), mounted tokens or platform metadata service. 

The certificate and JWTs encode namespace, trust domain, service account info - and 
may include cluster and project info.

[Istio environment](docs/istio_env.md) lists all settings, only a subset will be
required depending on the platform.

### Platform certificates

If the platform (CertManager, Spire, GKE) provisions each pod with 
a Spiffee certificate, all information needed is available in the environment.

### K8S with JWT token 

If JWT tokens are not disabled (which is an advanced option), all information can also be extracted from the token.

### VMs / containers / K8S without token



### Env and Defaults

- Root certificates for mesh communication:  - 
  /var/run/secrets/.... (platform provided roots), /etc/ssl/certs/ca-certificates.crt (Istio injected pods default), XDS_ROOT_CA, CA_ROOT_CA, system certificates. 

- Workload identity: 

- Trust domain: extracted from cert or JWT, TRUST_DOMAIN. For GKE expected to be PROJECT_ID.svc.id.goog format.

- Namespace: POD_NAMESPACE, extracted from cert/JWT

- Pod name: POD_NAME, hostname

- Service account: SERVICE_ACCOUNT, extracted from cert/JWT

### K8S Cluster

The availability of a K8S cluster will be detected and used to bootstrap:

- KUBECONFIG env variable, ${HOME}/.kube/config - default cluster will be configured, 
  and if name contains "_" will be interpreted as VENDOR_PROJECT_LOCATION_CLUSTER (gke style)

- in-cluster configs files

- 

### Certificate provider

In the absence of a 'platform certificate', the app should initiate 'commisioning'. 
This is provided by separate libraries, since it depends on gRPC ( ligher versions
also available for smaller binary size). 

- Default is istiod.istio-system.svc:15012, using the JWT in ...
- 

# Integration

Plugins:

- discovery mechanisms for destination metadata (for example XDS).
- certificate provisioning
- transports

## Certificates

The code will lookup certificates in the locations used in Istio/GKE and
generate certs for self-signed or testing. Includes the minimal CA
code, similar to Citadel.

## JWT

This library includes very minimal code to parse/verify JWT and extract info.
It is not complete or intended as a general library - just as a minimal one,
focused for the tokens used in K8S/Istio.

## Provisioning and bootstraping

Mesh auth provisioning involves configuring a core set of options:

- mesh and k8s root certificates
- private key or JWT
- a set of trusted servers for CA, XDS and further configuration.

The certs/JWT also include identity information that can be extracted - trust domain, namespace, etc.

## Webpush

This package also include the basic primitives for using Webpush - crypto and VAPID. While webpush is primarily
used for push messages to browsers, it is a very interesting mechanism for mesh config and events.

## STS

This is one of the more complicated pieces, getting google access tokens based on a
GKE token.

1. STS authentication starts with a GKE JWT with 'PROJECT.svc.id.goog' scope. You can mount it,
   or get it in exchange for the default token.
2. 'securetoken' API can exchange the token with a 'federated access token'
   This token can be used by some services, including in IAM policy bindings.
   In particular, it can be used with "workloadIdentiyUser" permission, to get tokens
   for another GSA.
3. Get token for a GSA, using https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s -
   either generateAccessToken or generateIdToken

It requires 3 round-trips, but can be cached and pre-fetched.

The most important is the federated exchange, which requires a token with
PROJECT_ID.svc.id.goog audience issued by a GKE cluster. Other IDP providers can
be used as well - with an associated federation config.

The federated token is a google access token associated with the 'foreign' K8S identity
which can be used directly by some services, or exchanged with a regular GSA that allows
delegation.

```bash


$ kubectl -n validation-temp-ns -c istio-proxy exec sleep-6758c4cb78-2gtpp -- \
  cat /var/run/secrets/tokens/istio-token >  istio-token

$ curl -v https://securetoken.googleapis.com/v1/identitybindingtoken -HContent-Type:application/json -d @exch.json


{"audience":"identitynamespace:costin-istio.svc.id.goog:https://container.googleapis.com/v1/projects/costin-istio/locations/us-west1-c/clusters/istio-test",
"subjectToken":"$(cat ISTIO_TOKEN)",
"grantType":"urn:ietf:params:oauth:grant-type:token-exchange",
"requestedTokenType":"urn:ietf:params:oauth:token-type:access_token",
"scope":"https://www.googleapis.com/auth/cloud-platform",
"subjectTokenType":"urn:ietf:params:oauth:token-type:jwt"}


Response:
{"access_token":"ya29.d.Ks...",
"issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
"token_type":"Bearer",
"expires_in":3600}



```
