# GCP auth

## Workload identity

If GKE is setup with WI enabled, it will run a custom MDS server and generate special JWT tokens.
A token mounted with the proper audience ( PROJECT_ID.svc.id.goog ) can be exchanged for a federated access token.

The MDS can return access and ID tokens - if the KSA is setup properly. Otherwise it only returns access tokens
for the federated account. Both the federated access token from MDS and the one exchanged from the mounted JWT
can be exchanged with GCP accounts - but MDS can do this automatically.

```shell
gcloud iam service-accounts create GSA_NAME --project=GSA_PROJECT

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member "serviceAccount:GSA_NAME@GSA_PROJECT.iam.gserviceaccount.com" \
  --role "ROLE_NAME"

# Allow KSA to impersonate ( workloadIdentityUser ) the GSA
gcloud iam service-accounts add-iam-policy-binding GSA_NAME@GSA_PROJECT.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:PROJECT_ID.svc.id.goog[NAMESPACE/KSA_NAME]"

# Allow SA to use quota from a different project 
gcloud projects add-iam-policy-binding \
  --role=roles/serviceusage.serviceUsageConsumer \
  --member=serviceAccount:PROJECT_ID.svc.id.goog[NAMESPACE/KSA_NAME] \
   QUOTA_PROJECT_ID

kubectl annotate serviceaccount KSA_NAME \
  --namespace NAMESPACE \
  iam.gke.io/gcp-service-account=GSA_NAME@GSA_PROJECT.iam.gserviceaccount.com

kubectl annotate serviceaccount KSA_NAME \
  --namespace NAMESPACE \
   iam.gke.io/credential-quota-project=QUOTA_PROJECT_ID

# Verify  
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email
  
```

The MDS is per node pool - so pods may need to be scheduled:

```yaml

spec:
  serviceAccountName: KSA_NAME
  nodeSelector:
    iam.gke.io/gke-metadata-server-enabled: "true"
```

# Secrets

```shell
gcloud secrets create bq-readonly-key \
    --data-file=manifests/bq-readonly-key \
    --ttl=3600s

gcloud iam service-accounts create readonly-secrets --display-name="Read secrets"
gcloud iam service-accounts create readwrite-secrets --display-name="Read write secrets"
 
gcloud secrets add-iam-policy-binding bq-readonly-key \
    --member=serviceAccount:readonly-secrets@PROJECT_ID.iam.gserviceaccount.com \
    --role='roles/secretmanager.secretAccessor'

gcloud secrets add-iam-policy-binding bq-readonly-key \
    --member=serviceAccount:readwrite-secrets@PROJECT_ID.iam.gserviceaccount.com \
    --role='roles/secretmanager.secretAccessor'
gcloud secrets add-iam-policy-binding bq-readonly-key \
    --member=serviceAccount:readwrite-secrets@PROJECT_ID.iam.gserviceaccount.com \
    --role='roles/secretmanager.secretVersionAdder'
    
gcloud iam service-accounts add-iam-policy-binding readonly-secrets@PROJECT_ID.iam.gserviceaccount.com \
    --member=serviceAccount:PROJECT_ID.svc.id.goog[readonly-ns/readonly-sa] \
    --role='roles/iam.workloadIdentityUser'
gcloud iam service-accounts add-iam-policy-binding readwrite-secrets@PROJECT_ID.iam.gserviceaccount.com \
    --member=serviceAccount:PROJECT_ID.svc.id.goog[admin-ns/admin-sa] \
    --role='roles/iam.workloadIdentityUser'

kubectl annotate serviceaccount readonly-sa \
    --namespace=readonly-ns \
    iam.gke.io/gcp-service-account=readonly-secrets@PROJECT_ID.iam.gserviceaccount.com
kubectl annotate serviceaccount admin-sa \
    --namespace=admin-ns \
    iam.gke.io/gcp-service-account=readwrite-secrets@PROJECT_ID.iam.gserviceaccount.com
    
 
```

# DNS Certificates

## CAS

## Public certs

# Workload Certificates

## MeshCA

## CAS

CAS can generate Spiffe certs in Istio format using [REFLECTED_SPIFFE"](https://cloud.google.com/certificate-authority-service/docs/using-identity-reflection)

That means the JWT used to authenticate is reflected into the spiffe URL SAN, and requires 
"roles/privateca.workloadCertificateRequester" permission and a 'federated token'.

roles/privateca.auditor	 - R/O access to all configs



