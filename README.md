# Minimal auth library for certs and tokens

The code is in large part based on/forked from Istio, to remove dependencies.

## Certificates

Code to lookup certificates in the locations used in Istio/GKE and 
generate certs for self-signed or testing. Includes the minimal CA
code, similar to Citadel.

## JWT

This library includes very minimal code to parse/verify JWT and extract info.
It is not complete or intended as a general library - just as a minimal one,
focused for the tokens used in K8S/Istio.

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

```bash


$ kubectl -n validation-temp-ns -c istio-proxy exec sleep-6758c4cb78-2gtpp -- cat /var/run/secrets/tokens/istio-token >  ../istiod/var/run/secrets/tokens/istio-token



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
