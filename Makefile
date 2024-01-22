include tools/common.mk

build: echo build/agent build/xmdsd

build/agent:
	mkdir -p ${OUT}
	(cd cmd && ${GOSTATIC} -o ${OUT}/meshauth-agent ./meshauth-agent)

build/xmdsd:
	mkdir -p ${OUT}
	(cd cmd && ${GOSTATIC} -o ${OUT}/xmdsd ./xmdsd)

push: push/agent push/xmdsd

push/agent:
	$(MAKE) _push BIN=meshauth-agent BASE_IMAGE=${BASE_DISTROLESS} GIT_REPO=meshauth

push/xmdsd:
	$(MAKE) _push BIN=xmdsd BASE_IMAGE=${BASE_DISTROLESS} GIT_REPO=meshauth

local:
	$(MAKE) _local BIN=meshauth-agent BASE_IMAGE=${BASE_DISTROLESS} DOCKER_REPO=${DOCKER_REPO}/meshauth
	$(MAKE) _local BIN=xmdsd DOCKER_REPO=${DOCKER_REPO}/meshauth

all: build push

BUILD_DIR?=/ws/out

wasm/meshauth:
	mkdir -p /tmp/tinygo
	docker run --rm -v $(shell pwd)/..:/src  -u $(shell id -u) \
      -v ${BUILD_DIR}/tinygo:/home/tinygo \
      -e HOME=/home/tinygo \
      -w /src/meshauth tinygo/tinygo:0.26.0 tinygo build -o /home/tinygo/wasm.wasm -target=wasm ./wasm/

deploy/httpbin:
	$(MAKE) _cloudrun MANIFEST=manifests/cloudrun/httpbin.yaml

deploy/xmdsd:
	$(MAKE) _cloudrun MANIFEST=manifests/cloudrun/xmdsd.yaml

test/httpbin:
	curl -v https://httpbin-yydsuf6tpq-uc.a.run.app/

WORKLOAD_NAMESPACE=istio-system

# Create a Google Service Account (GSA) associated with the k8s namespace in the config clusters.
# gcloud config set project PROJECT_ID
#
# Will grant 'clusterViewer' role, needed to list the config clusters (container.clusters,resourcemanager.projects)(.get,.list)
# TODO: document alternative (storing cluster config in mesh.env)
setup-gsa:
	gcloud --project ${PROJECT_ID} iam service-accounts create k8s-${WORKLOAD_NAMESPACE} \
      --display-name "Service account with access to ${WORKLOAD_NAMESPACE} k8s namespace" || true

	# Grant the GSA running the workload permission to connect to the config clusters in the config project.
	# Will use the 'SetQuotaProject' - otherwise the GKE API must be enabled in the workload project.
	gcloud --project ${CONFIG_PROJECT_ID} projects add-iam-policy-binding \
            ${CONFIG_PROJECT_ID} \
            --member="serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com" \
            --role="roles/container.clusterViewer"

	# This allows the GSA to use the GKE and other APIs in the 'config cluster' project.
	gcloud --project ${CONFIG_PROJECT_ID} projects add-iam-policy-binding \
            ${CONFIG_PROJECT_ID} \
            --member="serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com" \
            --role="roles/serviceusage.serviceUsageConsumer"

	# Also allow the use of TD
	gcloud projects add-iam-policy-binding ${PROJECT_ID} \
	  --member serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com \
	   --role roles/trafficdirector.client

setup-secrets:
	gcloud secrets create ca  --data-file ${HOME}/.ssh/ca.json

#	gcloud secrets create ca --location ${REGION} --datafile ${HOME}/.ssh/ca.json
#
#	gcloud secrets add-iam-policy-binding mesh \
#        --member=serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com \
#        --role="roles/secretmanager.secretAccessor"

	gcloud secrets add-iam-policy-binding ca \
        --member=serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com \
        --role="roles/secretmanager.secretAccessor"

#	gcloud run services add-iam-policy-binding  --region ${REGION} sshc  \
#      --member="allUsers" \
#      --role='roles/run.invoker'

SERVICE=xmdsd
CLUSTER?=mesh
CLUSTER_LOCATION?=us-central1-c
PROJECT_ID?=costin-asm1
REGION?=us-central1

export CLUSTER
export CLUSTER_LOCATION

gke/creds:
	 gcloud container clusters get-credentials ${CLUSTER} --region ${REGION} --project ${PROJECT_ID}


cr/user-perm:
	gcloud run services add-iam-policy-binding  --region ${REGION} xmdsd  \
      --member="user:${GCLOUD_USER}" \
      --role='roles/run.invoker'

# Allow current user to deploy cloudrun
cr/user-admin:
	gcloud projects add-iam-policy-binding ${PROJECT_ID}   \
      --member="user:${GCLOUD_USER}" \
      --role='roles/run.admin'

cr/deploy:
	#cat manifests/cloudrun/xmdsd.yaml | \
    #	DEPLOY="$(shell date +%H%M)" envsubst | \
    gcloud alpha run services replace manifests/cloudrun/xmdsd.yaml

cr/deploy2:
	cat manifests/cloudrun/httpbin.yaml | \
    	DEPLOY="$(shell date +%H%M)" envsubst | \
    gcloud alpha run services replace -


cr/test: CR_URL?=$(shell gcloud run services --project ${PROJECT_ID} --region ${REGION} describe ${SERVICE} --format="value(status.address.url)")
cr/test:
	@curl -v -H"Authorization: Bearer $(shell gcloud auth print-identity-token)" ${CR_URL}

cr/test2: CR_URL?=$(shell gcloud run services --project ${PROJECT_ID} --region ${REGION} describe httpbin --format="value(status.address.url)")
cr/test2:
	@curl -v -H"Authorization: Bearer $(shell gcloud auth print-identity-token)" ${CR_URL}/headers

gen-manifest:
	cat manifests/cloudrun/xmdsd.yaml | envsubst > manifests/cloudrun/xmdsd-gen.yaml

# Starting with k8s credentials
docker/run/k8s: _oci_local
	docker run -it --rm \
	   -v ${HOME}/.kube/config:/config -e KUBECONFIG=/config \
	    costinm/hbone:latest

# Starting with GCP credentials
docker/run/gcp: _oci_local
	docker run -it --rm \
	   -e GOOGLE_APPLICATION_CREDENTIALS=/gcp.json -v ${HOME}/.config/gcloud/application_default_credentials.json:/gcp.json \
	    costinm/hbone:latest
