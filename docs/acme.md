# ACME (RFC8555)

The ACME protocol is broadly deployed and well known. This document covers its use as a mesh
certificate provisioning protocol, and how to use it as a baseline protocol in this library.

ACME standard defines a mechansim for issuing certificates attesting some verifiable information.

ACME protocol has few steps. First is to create an account, based on a key pair. This may be 
skipped in the case of a mesh, if the ACME server is integrated with the identity provider
of the mesh it can use the K8S or IDP service accounts and proofs.

The second step is to prove ownership of a resource - by a sequence of requests resulting 
to a token proving the verification and assigning the domain to the account. An untrusted 
workload can't be expected to be able to do this - but the control plane can do it on its
behalf or issue tokens that are accepted by a mesh-aware ACME server.

Final step is to request the issuance and retrieve the certificate.

ACME uses JWS (Json tokens signed with the private key of the account) as a substitute to mTLS.

## ACME Mesh server

An ACME Mesh server is either a regular ACME server using the mesh control plane to assist
the mesh verification - or an extended server that is directly integrated with the mesh. For 
example it may verify a domain ownership and allow associating one or more K8S servers or IDPs with 
that account, using the signing key of the K8S/IDP to validate K8S-style JWTs and issue 
certs following a certain pattern. 

Assuming 'prod.example.com' ownership has been validated, the user using OOB or future ACME extensions could register the JWT signing key of cluster1.us-west and allow the auto-issuance
of certificates for httpbin.test.cluster1.us-west.prod.example.com for any user presenting a
JWT token with the proper audience and signed by the registered K8S. 

A control plane like Istio or a minimal specialized server can also implement the ACME protocol
steps and automate the integration - assuming the client code can append the required JWT to
either account creation or certificate signing request. 

## Protocol

ACME uses EC256 for the JWK and its own account. In case of mesh and workload identity it seems 
reasonable to use the private key of the workload for all authentication for the workload - so 
it should be used as the account key for ACME.

This is not specific to ACME - any server or protocol that involves non-mTLS transports could use
the same mechanism as ACME of using JWK singned by the private key of the workload. This will
be discussed in a separate doc. 

ACME defines a 'url' parameter in the JWK body which should match the authority and URL in the request.

If a 'regular ACME' server is used, the first steps of the protocol will be performed by the control
plane. The workload agent should only issue the final request. For a 'mesh-aware' ACME server that
is integrated with the mesh IDP, the final request should be issued directly to the ACME server.

## Prototype

WIP - this can be implemented without any other deps, reusing the Webpush JWK code. 
