package main_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/meln5674/gingk8s"
	"github.com/meln5674/gosh"
	. "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	. "github.com/onsi/gomega"
)

func TestKubeIngressProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "KubeIngressProxy Suite")
}

var (
	gk8s     gingk8s.Gingk8s
	gk8sOpts = gingk8s.SuiteOpts{
		KLogFlags: []string{"-v=6"},
		// Kubectl:        &localKubectl,
		// Helm:           &localHelm,
		// Manifests:      &localKubectl,
		NoSuiteCleanup: os.Getenv("KUBE_INGRESS_PROXY_E2E_DEV_MODE") != "",
		NoSpecCleanup:  os.Getenv("KUBE_INGRESS_PROXY_E2E_DEV_MODE") != "",
		NoCacheImages:  os.Getenv("IS_CI") != "",
		NoPull:         os.Getenv("IS_CI") != "",
		NoLoadPulled:   os.Getenv("IS_CI") != "",
	}

	kubeIngressProxyImage = gingk8s.CustomImage{
		Registry:   "local.host",
		Repository: "meln5674/kube-ingress-proxy",
	}

	lifenChartsRepo = gingk8s.HelmRepo{
		Name: "lifen-charts",
		URL:  "http://honestica.github.io/lifen-charts/",
	}
	squidChart = gingk8s.HelmChart{
		RemoteChartInfo: gingk8s.RemoteChartInfo{
			Repo:    &lifenChartsRepo,
			Name:    "squid",
			Version: "0.4.3",
		},
	}

	clusterID gingk8s.ClusterID
	clusterIP string

	clusterCertPool *x509.CertPool
)

var _ = BeforeSuite(func() {
	gk8s = gingk8s.ForSuite(GinkgoT())
	gk8s.Options(gk8sOpts)

	squidImageID := gk8s.ThirdPartyImage(&gingk8s.ThirdPartyImage{
		Name: "docker.io/honestica/squid:4.69",
	})
	nginxImageID := gk8s.ThirdPartyImage(&gingk8s.ThirdPartyImage{
		Name: "docker.io/bitnami/nginx:1.25.3",
	})
	ingressNginxControllerImageID := gk8s.ThirdPartyImage(&gingk8s.ThirdPartyImage{
		Name: "registry.k8s.io/ingress-nginx/controller:v1.7.0",
	})
	kubeIngressProxyImageID := gk8s.CustomImage(&kubeIngressProxyImage)
	calicoImagesID := gk8s.ThirdPartyImages(
		&gingk8s.ThirdPartyImage{
			Name: "docker.io/calico/cni:v3.26.1",
		},
		&gingk8s.ThirdPartyImage{
			Name: "docker.io/calico/kube-controllers:v3.26.1",
		},
		&gingk8s.ThirdPartyImage{
			Name: "docker.io/calico/node:v3.26.1",
		},
	)
	cluster := gingk8s.KindCluster{
		Name:           "kube-ingress-proxy-it",
		ConfigFilePath: "./integration-test/kind.config.yaml",
		TempDir:        "./integration-test/kind/",
	}
	clusterID = gk8s.Cluster(
		&cluster,
		calicoImagesID, squidImageID, ingressNginxControllerImageID, nginxImageID, kubeIngressProxyImageID,
	)
	gk8s.ClusterAction(clusterID, "Get Cluster IP", gingk8s.ClusterAction(func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
		Expect(gosh.Command(
			"docker", "inspect",
			fmt.Sprintf("%s-control-plane", cluster.(*gingk8s.KindCluster).Name),
			"-f", "{{ .NetworkSettings.Networks.kind.IPAddress }}").
			WithStreams(gosh.FuncOut(gosh.SaveString(&clusterIP))).
			Run(),
		).To(Succeed())

		clusterIP = strings.TrimSpace(clusterIP)
		return nil
	}))
	calicoID := gk8s.Manifests(
		clusterID,
		&gingk8s.KubernetesManifests{
			Name:          "Calico",
			ResourcePaths: []string{"./integration-test/calico.yaml"},
		},
		calicoImagesID,
	)

	networkPoliciesID := gk8s.Manifests(
		clusterID,
		&gingk8s.KubernetesManifests{
			Name:          "Infrastructure Network Policies",
			ResourcePaths: []string{"./integration-test/infra-network-policies.yaml"},
			SkipDelete:    true,
		},
		calicoID,
	)
	gk8s.Release(
		clusterID,
		&gingk8s.HelmRelease{
			Name:  "squid",
			Chart: &squidChart,
		},
		networkPoliciesID,
	)
	squidMariaDBID := gk8s.Release(
		clusterID,
		&gingk8s.HelmRelease{
			Name: "squid-auth-mariadb",
			Chart: &gingk8s.HelmChart{
				OCIChartInfo: gingk8s.OCIChartInfo{
					Registry: gingk8s.HelmRegistry{
						Hostname: "docker.io",
					},
					Repository: "bitnamicharts/mariadb",
					Version:    "15.1.2",
				},
			},
			Set: gingk8s.Object{
				"auth.username":     "squid",
				"auth.rootPassword": "root-password",
				"auth.password":     "password",
				"auth.database":     "squid",
			},
			SetFile: map[string]string{
				`initdbScripts.squid\.sql`: "./integration-test/squid.sql",
			},
		},
		networkPoliciesID,
	)
	squidAuthConfigID := gk8s.Manifests(
		clusterID,
		&gingk8s.KubernetesManifests{
			Name:          "Squid (Auth) Configuration",
			ResourcePaths: []string{"./integration-test/squid-auth-secret.yaml"},
		},
		squidMariaDBID,
	)
	gk8s.Release(
		clusterID,
		&gingk8s.HelmRelease{
			Name:  "squid-auth",
			Chart: &squidChart,
			Set: gingk8s.Object{
				"configSecret": "squid-auth",
			},
		},
		networkPoliciesID,
		squidAuthConfigID,
	)
	ingressNginxID := gk8s.Release(
		clusterID,
		&gingk8s.HelmRelease{
			Name: "ingress-nginx",
			Chart: &gingk8s.HelmChart{
				RemoteChartInfo: gingk8s.RemoteChartInfo{
					Repo: &gingk8s.HelmRepo{
						Name: "ingress-nginx",
						URL:  "https://kubernetes.github.io/ingress-nginx",
					},
					Name:    "ingress-nginx",
					Version: "4.6.0",
				},
			},
			Set: gingk8s.Object{
				"controller.service.type": "ClusterIP",
			},
		},
		networkPoliciesID,
		ingressNginxControllerImageID,
	)
	waitForIngressID := gk8s.ClusterAction(
		clusterID,
		"Wait for ingress",
		gingk8s.ClusterAction(func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
			defer g.Kubectl(ctx, cluster, "delete", "ingress", "sentinel").Run()
			for {
				err := g.Kubectl(ctx, cluster, "create", "-f", "integration-test/dummy-ingress.yaml").Run()
				if errors.Is(err, context.Canceled) {
					return err
				}
				if err == nil {
					return nil
				}
				GinkgoWriter.Printf("Failed to create sentinel ingress: %v\n", err)
				time.Sleep(15 * time.Second)
			}
		}),
		ingressNginxID,
	)
	nginx := gk8s.Release(
		clusterID,
		&gingk8s.HelmRelease{
			Name: "nginx",
			Chart: &gingk8s.HelmChart{
				OCIChartInfo: gingk8s.OCIChartInfo{
					Registry: gingk8s.HelmRegistry{
						Hostname: "docker.io",
					},
					Repository: "bitnamicharts/nginx",
					Version:    "15.8.1",
				},
			},
			Values: []gingk8s.NestedObject{{
				"service": gingk8s.NestedObject{
					"type": "ClusterIP",
				},
				"ingress": gingk8s.NestedObject{
					"enabled":          true,
					"tls":              true,
					"selfSigned":       true,
					"ingressClassName": "nginx",
					"annotations": gingk8s.NestedObject{
						"nginx.ingress.kubernetes.io/ssl-redirect":     "false",
						"nginx.ingress.kubernetes.io/backend-protocol": "HTTPS",
					},
				},
				"containerPorts": gingk8s.NestedObject{
					"https": 8443,
				},
				"extraVolumes": []gingk8s.NestedObject{{
					"name": "tls",
					"secret": gingk8s.NestedObject{
						"secretName": "nginx.local-tls",
					},
				}},
				"extraVolumeMounts": []gingk8s.NestedObject{{
					"name":      "tls",
					"mountPath": "/var/run/secrets/tls/",
				}},
			}},
			SetFile: map[string]string{
				"serverBlock": "./integration-test/nginx.conf",
			},
		},
		nginxImageID,
		waitForIngressID,
	)
	gk8s.ClusterAction(
		clusterID,
		"Get Nginx Certificate",
		gingk8s.ClusterAction(func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
			cert := gk8s.KubectlReturnSecretValue(ctx, cluster, "nginx.local-tls", "tls.crt")
			var err error
			clusterCertPool, err = x509.SystemCertPool()
			Expect(err).ToNot(HaveOccurred())
			clusterCertPool = clusterCertPool.Clone()
			clusterCertPool.AppendCertsFromPEM([]byte(cert))
			return nil
		}),
		nginx,
	)

	ctx, cancel := context.WithCancel(context.Background())
	DeferCleanup(cancel)
	gk8s.Setup(ctx)

})

var _ = Describe("Kube Ingress Proxy", func() {
	cases := map[string]func(gingk8s.Gingk8s, string) int64{
		"not using a second proxy":                     beforeNoSecondProxy,
		"using a second proxy over HTTP":               beforeSecondHTTPProxy,
		"using a second authenticated proxy over HTTP": beforeSecondHTTPAuthProxy,
	}
	for name, before := range cases {
		name := name
		before := before
		When(name, Ordered, func() {
			var proxyClient *http.Client
			var tr *http.Transport
			BeforeAll(func() {
				gk8s := gk8s.ForSpec()

				ns := gingk8s.RandomNamespace{}

				gk8s.ClusterAction(clusterID, "Random namespace", &ns)
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)
				gk8s.Setup(ctx)

				proxyPort := before(gk8s.ForSpec(), ns.Get())

				tr = http.DefaultTransport.(*http.Transport).Clone()
				tr.Proxy = func(*http.Request) (*url.URL, error) {
					return url.Parse(fmt.Sprintf("http://%s:%d", clusterIP, proxyPort))
				}
				tr.TLSClientConfig = &tls.Config{
					RootCAs: clusterCertPool,
				}
				proxyClient = &http.Client{Transport: tr}
			})
			DescribeTable(
				"should proxy",
				func(url string, host string) {
					var resp *http.Response
					do := func() (int, error) {
						req, err := http.NewRequest(http.MethodGet, url, nil)
						Expect(err).ToNot(HaveOccurred())
						req.Host = host
						tr.TLSClientConfig.ServerName = host
						proxy, err := tr.Proxy(req)
						Expect(err).ToNot(HaveOccurred())
						GinkgoLogr.Info("Will make request", "req", req, "proxy", proxy)
						ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(1*time.Second))
						DeferCleanup(cancel)
						resp, err = proxyClient.Do(req.WithContext(ctx))
						if err != nil {
							return -1, err
						}
						return resp.StatusCode, nil
					}
					Eventually(func() error { _, err := do(); return err }, "10s", "1s").Should(Succeed())
					Eventually(func() int { code, _ := do(); return code }, "10s", "1s").Should(Equal(http.StatusOK))
				},
				Entry("an internal HTTP service", "http://nginx.default.svc.cluster.local", ""),
				Entry("an internal HTTPS service", "https://nginx.default.svc.cluster.local", "nginx.local"),
				Entry("an HTTP ingress", "http://nginx.local", ""),
				Entry("an HTTPS ingress", "https://nginx.local", ""),
				Entry("an external HTTP service", "http://google.com", ""),
				Entry("an external HTTPS service", "https://google.com", ""),
			)
		})
	}
})

var (
	kubeIngressProxyChart = gingk8s.HelmChart{
		LocalChartInfo: gingk8s.LocalChartInfo{
			Path: "./deploy/helm/kube-ingress-proxy",
		},
	}
	kubeIngressProxyBaseValues = gingk8s.NestedObject{
		"controllerAddresses": []gingk8s.NestedObject{{
			"className": "nginx",
			"address":   "ingress-nginx-controller.default.svc.cluster.local",
		}},
		"service": gingk8s.NestedObject{
			"type": "NodePort",
		},
		"image": gingk8s.NestedObject{
			"repository": kubeIngressProxyImage.WithTag(""),
			"tag":        gingk8s.DefaultExtraCustomImageTags[0],
		},
		"logVerbosity": 10,
	}
)

func beforeNoSecondProxy(gk8s gingk8s.Gingk8s, ns string) int64 {
	name := "proxy-" + ns
	kubeIngressProxyID := gk8s.Release(
		clusterID,
		&gingk8s.HelmRelease{
			Chart:     &kubeIngressProxyChart,
			Name:      name,
			Namespace: ns,
			Values: []gingk8s.NestedObject{
				kubeIngressProxyBaseValues,
				{
					"fullnameOverride": name,
				},
			},
		},
	)
	var nodePort int64
	gk8s.ClusterAction(
		clusterID,
		"Get proxy NodePort",
		getProxyNodeport(ns, name, &nodePort),
		kubeIngressProxyID,
	)

	ctx, cancel := context.WithCancel(context.Background())
	DeferCleanup(cancel)
	gk8s.Setup(ctx)

	return nodePort
}

func beforeSecondHTTPProxy(gk8s gingk8s.Gingk8s, ns string) int64 {
	squidURL := "http://squid.default.svc.cluster.local:80"
	name := "proxy-" + ns
	kubeIngressProxyID := gk8s.Release(
		clusterID,
		&gingk8s.HelmRelease{
			Chart:     &kubeIngressProxyChart,
			Name:      name,
			Namespace: ns,
			Values: []gingk8s.NestedObject{
				kubeIngressProxyBaseValues,
				{
					"fullnameOverride": name,
					"extraEnv": []gingk8s.NestedObject{
						{"name": "HTTP_PROXY", "value": squidURL},
						{"name": "HTTPS_PROXY", "value": squidURL},
						{"name": "NO_PROXY", "value": "nginx.default.svc.cluster.local,nginx.local,10.96.0.1"},
						{"name": "http_proxy", "value": squidURL},
						{"name": "https_proxy", "value": squidURL},
						{"name": "no_proxy", "value": "nginx.default.svc.cluster.local,nginx.local,10.96.0.1"},
					},
				},
			},
		},
	)
	var nodePort int64
	gk8s.ClusterAction(
		clusterID,
		"Get proxy NodePort",
		getProxyNodeport(ns, name, &nodePort),
		kubeIngressProxyID,
	)

	ctx, cancel := context.WithCancel(context.Background())
	DeferCleanup(cancel)
	gk8s.Setup(ctx)

	return nodePort
}

func beforeSecondHTTPAuthProxy(gk8s gingk8s.Gingk8s, ns string) int64 {
	networkPoliciesID := gk8s.Manifests(
		clusterID,
		&gingk8s.KubernetesManifests{
			Name:          "Proxy Network Policies",
			ResourcePaths: []string{"./integration-test/auth-proxy-network-policies.yaml"},
		},
	)
	squidURL := "http://proxy-user@proxy-password@squid-auth.default.svc.cluster.local:80"
	name := "proxy-" + ns
	kubeIngressProxyID := gk8s.Release(
		clusterID,
		&gingk8s.HelmRelease{
			Chart:     &kubeIngressProxyChart,
			Name:      name,
			Namespace: ns,
			Values: []gingk8s.NestedObject{
				kubeIngressProxyBaseValues,
				{
					"fullnameOverride": name,
					"extraEnv": []gingk8s.NestedObject{
						{"name": "HTTP_PROXY", "value": squidURL},
						{"name": "HTTPS_PROXY", "value": squidURL},
						{"name": "NO_PROXY", "value": "nginx.default.svc.cluster.local,nginx.local,10.96.0.1"},
						{"name": "http_proxy", "value": squidURL},
						{"name": "https_proxy", "value": squidURL},
						{"name": "no_proxy", "value": "nginx.default.svc.cluster.local,nginx.local,10.96.0.1"},
					},
				},
			},
		},
		networkPoliciesID,
	)
	var nodePort int64
	gk8s.ClusterAction(
		clusterID,
		"Get proxy NodePort",
		getProxyNodeport(ns, name, &nodePort),
		kubeIngressProxyID,
	)

	ctx, cancel := context.WithCancel(context.Background())
	DeferCleanup(cancel)
	gk8s.Setup(ctx)

	return nodePort
}

func getProxyNodeport(ns, name string, nodePort *int64) gingk8s.ClusterAction {
	return gingk8s.ClusterAction(func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
		Eventually(func(match gomega.Gomega) int64 {
			var nodePortStr string
			match.Expect(g.
				Kubectl(
					ctx, cluster,
					"-n", ns,
					"get", "svc", name,
					"--template", "{{ (index .spec.ports 0).nodePort }}",
				).
				WithStreams(gosh.FuncOut(gosh.SaveString(&nodePortStr))).
				Run(),
			).To(Succeed())
			var err error
			*nodePort, err = strconv.ParseInt(nodePortStr, 10, 64)
			Expect(err).ToNot(HaveOccurred())
			return *nodePort
		}).ShouldNot(BeZero())
		return nil
	})
}
