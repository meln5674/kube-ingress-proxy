#!/bin/bash -xeu

which curl || (echo "curl not on PATH" ; exit 1)
which helm || (echo "helm not on PATH" ; exit 1)
which docker || (echo "docker not on PATH" ; exit 1)
which kubectl || (echo "kubectl not on PATH" ; exit 1)

TRAP_CMD=''

KIP_IT_CLEANUP=${KIP_IT_CLEANUP:-}
KIP_IT_NO_CLEANUP=${KIP_IT_NO_CLEANUP:-}
KIP_IT_NO_DOCKER_BUILD=${KIP_IT_NO_DOCKER_BUILD:-}


### Build Image

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

### Create Cluster

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
export http_proxy
export https_proxy

kubectl get pods -wAo wide &
GET_PODS_PID=$!
TRAP_CMD="kill ${GET_PODS_PID} ; ${TRAP_CMD}"
trap "set +e; ${TRAP_CMD}" EXIT

### Setup Helm

helm repo add istio https://istio-release.storage.googleapis.com/charts
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add jetstack https://charts.jetstack.io
helm repo update

### Deploy Infrastructure

ISTIO_VERSION=1.15.3

for ns in istio-system istio-ingress kube-ingress-proxy ingress-nginx cert-manager default ; do
    if ! kubectl get namespace ${ns} ; then
        kubectl create namespace ${ns}
    fi
    kubectl label namespace ${ns} istio-injection=disabled --overwrite=true
done

kubectl label namespace istio-ingress istio-injection=enabled --overwrite=true

helm upgrade cert-manager jetstack/cert-manager \
  --install \
  --wait \
  --debug \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true


helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
    --install \
    --wait \
    --debug \
    --namespace ingress-nginx \
    --set controller.service.type=ClusterIP \
    --set controller.extraArgs.default-ssl-certificate=ingress-nginx/ingress-cert


WORDPRESS_HOST=wordpress.some.non-existent.domain

if kubectl get deploy wordpress ; then
    kubectl rollout restart sts/wordpress-mariadb
    kubectl rollout status sts/wordpress-mariadb
    kubectl rollout restart deploy/wordpress
    kubectl rollout status deploy/wordpress
fi

helm upgrade wordpress bitnami/wordpress \
    --install \
    --wait \
    --debug \
    --set ingress.enabled=true \
    --set ingress.hostname="${WORDPRESS_HOST}" \
    --set ingress.ingressClassName=nginx \
    --set ingress.extraTls[0].hosts[0]="${WORDPRESS_HOST}" \
    --set service.type=ClusterIP \
    --set image.debug=true \
    --set mariadb.image.debug=true \
    --set peristence.enabled=true

kubectl rollout restart sts/wordpress-mariadb
kubectl rollout status sts/wordpress-mariadb
kubectl rollout restart deploy/wordpress
kubectl rollout status deploy/wordpress

helm upgrade istio-base istio/base \
    --version=${ISTIO_VERSION} \
    --install \
    --debug \
    --wait \
    --namespace istio-system \

helm upgrade istiod istio/istiod \
    --version=${ISTIO_VERSION} \
    --install \
    --debug \
    --wait \
    --namespace istio-system \
    --set global.proxy.componentLogLevel=misc:debug \
    --set global.proxy.logLevel=trace \
    --set global.proxy.tracer="none"

helm upgrade gateway istio/gateway \
    --version=${ISTIO_VERSION} \
    --install \
    --debug \
    --wait \
    --namespace istio-ingress \
    --set service.type=NodePort

kubectl -n istio-system rollout restart deploy/istiod
kubectl -n istio-system rollout status deploy/istiod

kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ca
  namespace: cert-manager
spec:
  isCA: true
  commonName: ca
  secretName: root-secret
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned-issuer
    kind: ClusterIssuer
    group: cert-manager.io
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ca
spec:
  ca:
    secretName: root-secret
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ingress
  namespace: ingress-nginx
spec:
  # Secret names are always required.
  secretName: ingress-cert
  duration: 2160h # 90d
  renewBefore: 360h # 15d
  isCA: false
  privateKey:
    algorithm: RSA
    encoding: PKCS1
    size: 2048
  dnsNames:
    - '*.some.non-existent.domain'
  issuerRef:
    name: ca
    kind: ClusterIssuer
    group: cert-manager.io
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: gateway
  namespace: istio-ingress
spec:
  # Secret names are always required.
  secretName: gateway-cert
  duration: 2160h # 90d
  renewBefore: 360h # 15d
  isCA: false
  privateKey:
    algorithm: RSA
    encoding: PKCS1
    size: 2048
  dnsNames:
    - '*.istiocluster.dev'
  issuerRef:
    name: ca
    kind: ClusterIssuer
    group: cert-manager.io
---
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: default
spec:
  selector:
    istio: gateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*.istiocluster.dev"
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: gateway-cert
    hosts:
    - "*.istiocluster.dev"
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: wordpress.default.svc.cluster.local
spec:
  hosts:
  - "wordpress.istiocluster.dev"
  gateways:
  - default
  http:
  - route:
    - destination:
        port:
          number: 80
        host: wordpress.default.svc.cluster.local
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: wordpress-mariadb
spec:
  hosts:
  - "wordpress-mariadb.istiocluster.dev"
  tcp:
  - route:
    - destination:
        port:
          number: 3306
        host: wordpress-mariadb.default.svc.cluster.local
---
EOF

    ### Case: Ingress, Port-Forward, All Namespaces

    http_proxy=
    https_proxy=

    helm upgrade kube-ingress-proxy ./deploy/helm/kube-ingress-proxy \
       --install \
       --wait \
       --debug \
       --namespace kube-ingress-proxy \
       --set image.repository="${IMAGE_REPO}" \
       --set image.tag="${IMAGE_TAG}" \
       --set controllerAddresses[0].className=nginx \
       --set controllerAddresses[0].address=ingress-nginx-controller.ingress-nginx.svc.cluster.local \
       --set logVerbosity=10


    kubectl -n kube-ingress-proxy rollout restart ds/kube-ingress-proxy
    kubectl -n kube-ingress-proxy rollout status ds/kube-ingress-proxy

    kubectl -n kube-ingress-proxy port-forward svc/kube-ingress-proxy 8080:80 &
    PORT_FORWARD_PID=$!
    TRAP_CMD="kill ${PORT_FORWARD_PID} ; ${TRAP_CMD}"
    trap "set +e; ${TRAP_CMD}" EXIT

    sleep 10

    http_proxy=http://localhost:8080
    https_proxy=http://localhost:8080

    curl -fvkL "http://${WORDPRESS_HOST}"
    curl -fvkL "https://${WORDPRESS_HOST}"

    echo 'Test Port Forward, Ingress, Cluster-scoped: Passed!"

    ### Case: Ingress, Host Port, All Namespaces

    http_proxy=
    https_proxy=

    helm upgrade kube-ingress-proxy ./deploy/helm/kube-ingress-proxy \
       --install \
       --wait \
       --debug \
       --namespace kube-ingress-proxy \
       --set image.repository="${IMAGE_REPO}" \
       --set image.tag="${IMAGE_TAG}" \
       --set controllerAddresses[0].className=nginx \
       --set controllerAddresses[0].address=ingress-nginx-controller.ingress-nginx.svc.cluster.local \
       --set logVerbosity=10 \
       --set hostPort.enabled=true \
       --set hostPort.port=9090

    kubectl -n kube-ingress-proxy rollout restart ds/kube-ingress-proxy
    kubectl -n kube-ingress-proxy rollout status ds/kube-ingress-proxy

    sleep 10
    http_proxy=http://localhost:9090
    https_proxy=http://localhost:9090

    curl -fvkL "http://${WORDPRESS_HOST}"
    curl -fvkL "https://${WORDPRESS_HOST}"

    echo 'Test Host Port, Ingress, Cluster-scoped: Passed!"


    ### Case: Ingress, Host Port, Single Namespace

    http_proxy=
    https_proxy=

    helm upgrade kube-ingress-proxy ./deploy/helm/kube-ingress-proxy \
       --install \
       --wait \
       --debug \
       --namespace kube-ingress-proxy \
       --set image.repository="${IMAGE_REPO}" \
       --set image.tag="${IMAGE_TAG}" \
       --set controllerAddresses[0].className=nginx \
       --set controllerAddresses[0].address=ingress-nginx-controller.ingress-nginx.svc.cluster.local \
       --set logVerbosity=10 \
       --set hostPort.enabled=true \
       --set hostPort.port=9090 \
       --set rbac.allNamespaces=false \
       --set rbac.namespaces[0]=default

    kubectl -n kube-ingress-proxy rollout restart ds/kube-ingress-proxy
    kubectl -n kube-ingress-proxy rollout status ds/kube-ingress-proxy

    sleep 10

    http_proxy=http://localhost:9090
    https_proxy=http://localhost:9090

    curl -fvkL "http://${WORDPRESS_HOST}"
    curl -fvkL "https://${WORDPRESS_HOST}"

    echo 'Test Host Port, Ingress, Namespaced: Passed!"


    ### Case: Istio, Host Port, Single Namespace

    http_proxy=
    https_proxy=

    kubectl label namespace default istio-injection=enabled --overwrite=true
    kubectl rollout restart sts/wordpress-mariadb
    kubectl rollout status sts/wordpress-mariadb
    kubectl rollout restart deploy/wordpress
    kubectl rollout status deploy/wordpress

    WORDPRESS_HOST=wordpress.istiocluster.dev

    helm upgrade kube-ingress-proxy ./deploy/helm/kube-ingress-proxy \
       --install \
       --wait \
       --debug \
       --namespace kube-ingress-proxy \
       --set image.repository="${IMAGE_REPO}" \
       --set image.tag="${IMAGE_TAG}" \
       --set istio.enabled=true \
       --set istio.gatewayAddresses[0].namespace=default \
       --set istio.gatewayAddresses[0].name=default \
       --set istio.gatewayAddresses[0].address=gateway.istio-ingress.svc.cluster.local \
       --set logVerbosity=10 \
       --set hostPort.enabled=true \
       --set hostPort.port=9090 \
       --set rbac.allNamespaces=false \
       --set rbac.namespaces[0]=default

    kubectl -n kube-ingress-proxy rollout status ds/kube-ingress-proxy

    sleep 10

    http_proxy=http://localhost:9090
    https_proxy=http://localhost:9090

    curl -fvkL "http://${WORDPRESS_HOST}"
    curl -fvkL "https://${WORDPRESS_HOST}"

    echo 'Test Host Port, Istio, Namespaced: Passed!'

kill %1

echo Passed!
