# Minimal mesh-focused auth library

This is an attempt to have a minimal, low-resource/WASM friendly library with no
external dependencies encapsulating the most common mesh auth and 
provisioning patterns.

The code is in large part based on/forked from Istio and few of my projects,
to remove dependencies  and extract the minimum required.

## Goals

- minimal code - only auth features commonly used in mesh, with no external dependency
- provide common networking abstractions and platform adapters, but without 
large dependencies and using a common model for gRPC/REST/K8S-REST.

The platform and k8s integrations are focused on bootstraping and getting tokens.

## Config

Provisioning and config are separated from 'mesh' - Istio is using gRPC/XDS, but
ztunnel can also use a local config file. XDS is a big dependency, as is K8S
client library.

I am also more interested in signed configurations - where the transport doesn't
matter and control plane is not trusted (zero-trust).

Unlike Istio - 'on demand' is the only option. Pushing all configs (SOW) is possible,
with the configs saved to disk (cached) and still loaded on demand.



## Certs and Tokens

It is my belief that 'certificates' and 'tokens' are about the same thing -
signed claims, using JSON or DER format (or CBOR, etc). As such, every
workload, every user, config providers are expected to have (at least) 
one private key and to configure at least one trusted 'mesh root'.

Unlike Istio, the relation is very granular (and 'federated') - a workload may
only trust the public key of the workload owner (whoever operates the workload
and has platform permission to exec and run the code on the specific machine), 
so each deployment and 'service account' can have a different root of trust.

Configs determine the signer for each destination - and may use different sources
or mechanisms, including public CA infra, public DNS(SEC), private DNSSEC or any
other mechanism appropriate for the service. The configs are either signed or
retrieved from a trusted source (like a trusted control plane)

### Certs

The certs package has many helpers to work with certificates - including a
CA, similar to Istio Citadel but minimized.

The 'internet certificates' rely on 'certificate authorities', which have a huge
power (can sign any domain). The Internet CAs have the 'isCA' bit set, and 
verification of internet cert chains requires the isCA bit.

However, a 'cert' without 'isCA' is still a claim, under the authority
of the signer - just like a JWT issued by an IDP. The JWT provider is not 
trusted for all identities on the internet - only for a domain. 

Just like OIDC or ATproto bootstrap the trust for a FQDN by did:web or the
'well known' public keys, a signing key for certificates associated with a domain
can be configured or loaded.


### Tokens

This library includes very minimal code to parse/verify JWT and extract info.
It is not complete or intended as a general library - just as a minimal one,
focused for the tokens used in K8S/Istio - as well as Webpush VAPID tokens.

It includes both verification and issuing/signing code. Like certificates, any 
workload can sign 'claims'.


## Webpush

This package also include the basic primitives for using Webpush - crypto and VAPID. While webpush is primarily used for push messages to browsers, it is a very interesting mechanism for mesh config and events.

## Packages

- certs: utils around certificate signing, verification. Deps free.
- tokens: utils around token signing, verification - including OIDC. Deps free.
- webpush: encrypt/decrypt - VAPID is in tokens.
- xnet: retry and network helpers.
- meshauth(certs,tokens): Dest and common mesh properties.
- uk8s(tokens,meshauth,xnet): utils around K8S tokens and raw access - not using K8S libs
- ugcp(tokens,xnet,meshauth,xnet): utils around GCP integration (not using GCP libs) - MDS, STS, etc


### Environment and Defaults


The certs/JWT also include identity information that can be extracted - trust domain, namespace, etc.

- Root certificates for mesh communication:  -
  /var/run/secrets/.... (platform provided roots), /etc/ssl/certs/ca-certificates.crt (Istio injected pods default), XDS_ROOT_CA, CA_ROOT_CA, system certificates.

- Workload identity: cert provisioned by CertManager, Istio, etc

- Trust domain: extracted from cert or JWT, TRUST_DOMAIN. For GKE expected to be PROJECT_ID.svc.id.goog format.

- Namespace: POD_NAMESPACE, extracted from cert/JWT

- Pod name: POD_NAME, hostname

- Service account: SERVICE_ACCOUNT, extracted from cert/JWT
