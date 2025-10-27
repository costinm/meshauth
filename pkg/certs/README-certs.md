# Certificates

Original idea was close to Istio, with certificates at the core. 
Unfortunately URL certs adds too much complexity and the private protocols
are unlikely to be broadly adopted.

I realized that tokens are far more flexible and better suited for messaging - and for certs using ACME is easy enough. Having a 
mechanism to generate private certificates is still useful - but 
it can be far more flexible and simpler than traditional Istio
or Kubernetes certs.


## Private DNS certificates

Each node is expected to either load a cert or generate a self-signed
one. The private key is used for all signing.

## Delegation

A node can identify itself - but can act on behalf of other nodes (actAs).

This is similar to token delegation, but with certificates.


### CAa are not special

There is a wide belief that signing a certificate is a very special thing
and that CAs are the root of trust. 

Any private key can be used to sign JWTs, certificates or anything else.
What makes a private keys 'special' is that the public key is configured
as 'trusted' for certain things - can be 'verify a specific identity'



We will also generate a self-signed root CA based on the same key, and
use it to sign certificates for any domain. The client needs to specify
this node public key as the trusted root.

A parent CA can also be used - clients would use the parent CA as 'trusted'
for the set of domains that are delegated to this node.
