#!/bin/bash -xeu

which curl || (echo "curl not on PATH" ; exit 1)
which helm || (echo "helm not on PATH" ; exit 1)
which docker || (echo "docker not on PATH" ; exit 1)
which kubectl || (echo "kubectl not on PATH" ; exit 1)

TRAP_CMD=''

KIP_IT_CLEANUP=${KIP_IT_CLEANUP:-}
KIP_IT_NO_CLEANUP=${KIP_IT_NO_CLEANUP:-}
KIP_IT_NO_DOCKER_BUILD=${KIP_IT_NO_DOCKER_BUILD:-}


TEST_TIMESTAMP=$(date +%s)
IMAGE_REPO=${IMAGE_REPO:-local.host/meln5674/kube-ingress-proxy}
if [ -z "${KIP_IT_CLEANUP}" ] && [ -z "${KIP_IT_NO_DOCKER_BUILD}" ] ; then
    IMAGE_TAG=${IMAGE_TAG:-${TEST_TIMESTAMP}}
    BUILT_IMAGE=${IMAGE_REPO}:${IMAGE_TAG}
    export DOCKER_BUILDKIT=1
    docker build -t "${BUILT_IMAGE}" .
    echo "${BUILT_IMAGE}" > integration-test/last-image
else
    BUILT_IMAGE=$(cat integration-test/last-image)
    IMAGE_REPO=$(awk -F ':' '{ print $1 }' <<< "${BUILT_IMAGE}")
    IMAGE_TAG=$(awk -F ':' '{ print $2 }' <<< "${BUILT_IMAGE}")
fi

KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME=kip-it}
CLUSTER_EXISTS="$(
    if kind get clusters | grep -qw "${KIND_CLUSTER_NAME}" ; then
        echo 1
    fi
)"

KIND_KUBECONFIG=./integration-test/kind.kubeconfig
if [ -z "${CLUSTER_EXISTS}" ] || ([ -n "${CLUSTER_EXISTS}" ] && [ -z "${KIP_IT_NO_CLEANUP}" ] && [ -z "${KIP_IT_CLEANUP}" ]); then
    KIND_CONFIG_FILE=integration-test/kind.config.yaml
    kind create cluster \
        --name="${KIND_CLUSTER_NAME}" \
        --kubeconfig="${KIND_KUBECONFIG}" \
        --config="${KIND_CONFIG_FILE}"
fi

if [ -z "${KIP_IT_NO_CLEANUP}" ]; then
    # TODO: Use a temporary root container instead of sudo here
    TRAP_CMD="kind delete cluster --name='${KIND_CLUSTER_NAME}' ; ${TRAP_CMD}"
    trap "set +e; ${TRAP_CMD}" EXIT
fi


if [ -z "${KIP_IT_CLEANUP}" ] ; then
    kind load docker-image "${BUILT_IMAGE}" --name="${KIND_CLUSTER_NAME}"
fi

if [ -n "${KIP_IT_CLEANUP}" ]; then
    kind delete cluster --name='${KIND_CLUSTER_NAME}'
    exit 0
fi


export KUBECONFIG="${KIND_KUBECONFIG}"


helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
    --install \
    --wait \
    --debug \
    --set controller.service.type=ClusterIP

WORDPRESS_HOST=wordpress.some.non-existent.domain

helm upgrade wordpress bitnami/wordpress \
    --install \
    --wait \
    --debug \
    --set ingress.enabled=true \
    --set ingress.hostname="${WORDPRESS_HOST}" \
    --set ingress.ingressClassName=nginx \
    --set ingress.extraTls[0].hosts[0]="${WORDPRESS_HOST}" \
    --set service.type=ClusterIP

helm upgrade kube-ingress-proxy ./deploy/helm/kube-ingress-proxy \
   --install \
   --wait \
   --debug \
   --set image.repository="${IMAGE_REPO}" \
   --set image.tag="${IMAGE_TAG}" \
   --set controllerAddresses[0].className=nginx \
   --set controllerAddresses[0].address=ingress-nginx-controller.default.svc.cluster.local \
   --set logVerbosity=10

kubectl rollout status ds/kube-ingress-proxy

kubectl port-forward svc/kube-ingress-proxy 8080:80 &
PORT_FORWARD_PID=$!
TRAP_CMD="kill ${PORT_FORWARD_PID} ; ${TRAP_CMD}"
trap "set +e; ${TRAP_CMD}" EXIT

sleep 10

http_proxy=http://localhost:8080 https_proxy=http://localhost:8080 curl -fvkL "http://${WORDPRESS_HOST}"
https_proxy=http://localhost:8080 curl -fvkL "https://${WORDPRESS_HOST}"

kill %1

helm upgrade kube-ingress-proxy ./deploy/helm/kube-ingress-proxy \
   --install \
   --wait \
   --debug \
   --set image.repository="${IMAGE_REPO}" \
   --set image.tag="${IMAGE_TAG}" \
   --set controllerAddresses[0].className=nginx \
   --set controllerAddresses[0].address=ingress-nginx-controller.default.svc.cluster.local \
   --set logVerbosity=10 \
   --set hostPort.enabled=true \
   --set hostPort.port=9090

kubectl rollout status ds/kube-ingress-proxy

sleep 10

http_proxy=http://localhost:9090 https_proxy=http://localhost:9090 curl -fvkL "http://${WORDPRESS_HOST}"
https_proxy=http://localhost:9090 curl -fvkL "https://${WORDPRESS_HOST}"

echo Passed!
