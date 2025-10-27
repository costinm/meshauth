# Minimal GCP integration

Package micro GCP includes dependency free code to get tokens and interact with GCP.

This includes a GCP (minimally compatible) MDS server for testing and using apps
expecting GCP MDS.


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

