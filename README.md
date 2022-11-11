# Kubernetes Ingress Proxy

## What?

This tool is intended to be used to ease development and debugging of applications deployed into local Kubernetes cluster which may make using Ingress challenging.

## Why?

If you have a local Kubernetes cluster, and would like to test applications over ingress, you will likely need to modify your /etc/hosts file. In some cases, you may not have the permissions to do so. If using WSL, then even if you can modify your WSL /etc/hosts file, then you still cannot reach those hostnames from within, say, a web browser running on the host Windows OS.

There are three main use cases this tool is tailored for:

1. You have a localhost cluster, but don't have access to your own /etc/hosts file, but still want to use an ingress controller
2. You have a localhost cluster, have access to your /etc/hosts file, but are using so many ingresses that it would be a pain to add all of the entries by hand
3. You need to access a service by its ingress hostname (such as an SSO provider), but those hostnames aren't backed by an external DNS server

In most cases, this tool is best suited for development and test environments.

As a byproduct of how this tool is implemented, you will also be able to access services by their `<name>.<namespace>.svc.cluster.local`-style hostnames.

## How?

This tool operates as a pod within your local cluster, and scans all namespaces (or a subset) for Ingress resources. It maintains its own custom /etc/hosts files, and exposes an HTTP proxy. You can expose this tool on a NodePort-type Service, using a container hortPort, or just using `kubectl port-forward` and configure your system to use it as a proxy.

## Getting Started

If you've got the [ingress-nginx](https://github.com/kubernetes/ingress-nginx/) installed in the `ingress-nginx` namespace, install the proxy like this

```bash
helm repo add https://meln5674.github.io/k8s-ingress-proxy
helm upgrade k8s-ingress-proxy/k8s-ingress-proxy \
    --install \
    --wait \
    --set controllerAddresses[0].className=nginx \
    --set controllerAddresses[0].address=ingress-nginx-controller.ingress-nginx.svc.cluster.local
```

Now if you've got the following ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: some-ingress
rules:
- host: some.internal.hostname
  # ...
tls:
- hosts:
  - some.internal.hostname
  # ...

```

You can access it like this

```bash
kubectl port-forward svc/k8s-ingress-proxy 8080:80 &
# Give it a second to start
sleep 5

http_proxy=http://localhost:8080 curl -v http://some.internal.hostname
# HTTPS also works
https_proxy=http://localhost:8080 curl -v https://some.internal.hostname

# Stop the port forward
kill %1
```

To set up a persistent port, you can install it like this

```bash
helm repo add https://meln5674.github.io/k8s-ingress-proxy
helm upgrade k8s-ingress-proxy/k8s-ingress-proxy \
    --install \
    --wait \
    --set controllerAddresses[0].className=nginx \
    --set controllerAddresses[0].address=ingress-nginx-controller.ingress-nginx.svc.cluster.local \
    --set hostPort.enabled \
    --set hostPort.port=8080 # Defaults to 8080
```

If using Kind, make sure to add an extra section as shown [here](https://kind.sigs.k8s.io/docs/user/configuration/#extra-port-mappings) to have this port exposed.

If using Chrome (or one of it's cousings such as Brave or Edge), go to [this page](brave://settings/system) to set `http://localhost:<hostPort.port from above>` as both the http and https proxy. For Firefox, go [here](about:preferences) and go to "Network Setttings: to set this.

After doing this, you'll be able to debug your services and ingresses straight in your browser, as well as utilize browser-based test frameworks such as Selenium or Karma. Just make sure to revert these settings once you're done.
