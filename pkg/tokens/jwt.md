# JWTs

This package is focused on JWTs - issuing, verifying, exchanging and using a subset of JWTs with no external dependencies.

Unlike typical JWT libraries where the 'Identity Provider' is very special - it treats anyone with a private key as a potential JWT issuer.


## Issuing JWTs

The Tokens module is configured with a private key and a FQDN. It can issue tokens
using that FQDN as 'iss', and serve the public keys using a minimal
 subset of OIDC and DID:web.

That means any workload can issue tokens as long as it has a private key and a verifiable FQDN.


## Public key and Verification

A JWT encodes 'iss' and the key ID, which are used to identify the public key that signed the JWT. As long as a configuration 'trusts' the issuer for the token 'sub' - it is valid.

The 'trust' is based on a config associating an
'iss' with a public key and a policy on which 
kind of tokens are allowed.

## Self-issued JWTs

The public key can be stored as DID:web.

## DNS 

The public key can also be stored in DNS. 



