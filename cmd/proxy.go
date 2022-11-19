/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"bufio"
	"context"
	"errors"
	goflag "flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/spf13/cobra"
	istio "istio.io/client-go/pkg/apis/networking/v1alpha3"
	istiocfg "istio.io/client-go/pkg/clientset/versioned"
	istioinformers "istio.io/client-go/pkg/informers/externalversions"
	istiov1a3inf "istio.io/client-go/pkg/informers/externalversions/networking/v1alpha3"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	k8sinformers "k8s.io/client-go/informers"
	networkingv1inf "k8s.io/client-go/informers/networking/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

const (
	noLimit                = -1
	verboseProxyDebugLevel = 2
)

var (
	etcHosts             string
	backupEtcHosts       string
	ignoreBackupEtcHosts bool

	listenAddress       string
	ingressClassMapping map[string]string

	istioEnabled        bool
	istioGatewayMapping map[string]string

	k8sOverrides   clientcmd.ConfigOverrides
	kubeconfigPath string
	allNamespaces  bool
	namespaces     []string

	whitespacePattern = regexp.MustCompile(`\s+`)
	commentPattern    = regexp.MustCompile(`^(\s*#.*)?$`)

	klogFlags *goflag.FlagSet
)

type hostsFileRecord struct {
	comment       []string
	address       string
	canonicalName string
	aliases       []string
}

func (r *hostsFileRecord) lines() []string {
	out := make([]string, len(r.comment), len(r.comment)+1)
	copy(out, r.comment)
	line := strings.Builder{}
	line.WriteString(fmt.Sprintf("%s %s", r.address, r.canonicalName))
	for _, alias := range r.aliases {
		line.WriteString(" ")
		line.WriteString(alias)
	}
	out = append(out, line.String())

	return out
}

type hostsFile struct {
	records       []hostsFileRecord
	footerComment []string
}

func parseHostsFile(s *bufio.Scanner) (*hostsFile, error) {
	f := hostsFile{
		records: []hostsFileRecord{},
	}
	commentBuf := []string{}
	for s.Scan() {
		line := s.Text()
		if commentPattern.MatchString(line) {
			commentBuf = append(commentBuf, line)
			continue
		}
		fields := whitespacePattern.Split(line, noLimit)
		if len(fields) < 2 {
			return nil, fmt.Errorf("Invalid line %s, must have at least an address and hostname", line)
		}
		f.records = append(f.records, hostsFileRecord{
			comment:       commentBuf,
			address:       fields[0],
			canonicalName: fields[1],
			aliases:       fields[2:],
		})
		commentBuf = []string{}
	}
	err := s.Err()
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func readHostsFile(r io.Reader) (*hostsFile, error) {
	return parseHostsFile(bufio.NewScanner(r))
}

func loadHostsFile(path string) (*hostsFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readHostsFile(f)
}

func (f *hostsFile) lines() []string {
	out := make([]string, 0)
	for _, record := range f.records {
		out = append(out, record.lines()...)
		out = append(out, "")
	}
	out = append(out, f.footerComment...)
	return out
}

func (f *hostsFile) write(w io.Writer) error {
	for _, line := range f.lines() {
		_, err := w.Write([]byte(line))
		if err != nil {
			return err
		}
		_, err = w.Write([]byte("\n"))
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *hostsFile) writeToFile(path string) error {
	fp, err := os.Create(path)
	if err != nil {
		return err
	}
	return f.write(fp)
}

type host struct {
	name    string
	address string
}

func (f *hostsFile) buildHosts(controllers map[string]host, gateways map[string]host) hosts {
	h := hosts{
		baseRecords:   f.records,
		footerComment: f.footerComment,
		controllers:   make(map[string]controller, len(controllers)),
		gateways:      make(map[string]gateway, len(gateways)),
	}
	for className, host := range controllers {
		h.controllers[className] = controller{host: host, aliases: map[string]map[string]struct{}{}, className: className}
	}
	for gatewayID, host := range gateways {
		h.gateways[gatewayID] = gateway{host: host, aliases: map[string]map[string]struct{}{}, id: gatewayID}
	}
	return h
}

func getIngressID(ingress *networkingv1.Ingress) string {
	return fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Name)
}

func getVirtualServiceID(vs *istio.VirtualService) string {
	return fmt.Sprintf("%s/%s", vs.Namespace, vs.Name)
}

func getGatewayID(gw *istio.Gateway) string {
	return fmt.Sprintf("%s/%s", gw.Namespace, gw.Name)
}
func getIngressClass(ingress *networkingv1.Ingress) string {
	if ingress.Spec.IngressClassName != nil {
		return *ingress.Spec.IngressClassName
	}
	return ingress.Annotations["kubernetes.io/ingress.class"]
}

func getVirtualServiceGateway(vs *istio.VirtualService) string {
	if len(vs.Spec.Gateways) == 0 {
		return ""
	}
	if strings.Contains(vs.Spec.Gateways[0], "/") {
		return vs.Spec.Gateways[0]
	}
	return fmt.Sprintf("%s/%s", vs.Namespace, vs.Spec.Gateways[0])
}

type controller struct {
	host
	className string
	aliases   map[string]map[string]struct{}
}

type gateway struct {
	host
	id      string
	aliases map[string]map[string]struct{}
}

type hosts struct {
	baseRecords   []hostsFileRecord
	footerComment []string

	controllers map[string]controller
	gateways    map[string]gateway
}

func (h *hosts) buildHostsFile() *hostsFile {
	command := strings.Join(os.Args, " ")
	f := hostsFile{
		footerComment: h.footerComment,
		records:       make([]hostsFileRecord, 0, len(h.baseRecords)),
	}
	f.records = append(f.records, h.baseRecords...)
	for _, controller := range h.controllers {
		allAliases := map[string]struct{}{}
		for _, aliases := range controller.aliases {
			for alias := range aliases {
				allAliases[alias] = struct{}{}
			}
		}
		aliases := []string{}
		for alias := range allAliases {
			aliases = append(aliases, alias)
		}
		f.records = append(f.records, hostsFileRecord{
			comment:       []string{fmt.Sprintf("# Generated by %s for ingress class %s", command, controller.className)},
			address:       controller.address,
			canonicalName: controller.name,
			aliases:       aliases,
		})
	}
	for _, gateway := range h.gateways {
		allAliases := map[string]struct{}{}
		for _, aliases := range gateway.aliases {
			for alias := range aliases {
				allAliases[alias] = struct{}{}
			}
		}
		aliases := []string{}
		for alias := range allAliases {
			aliases = append(aliases, alias)
		}
		f.records = append(f.records, hostsFileRecord{
			comment:       []string{fmt.Sprintf("# Generated by %s for gateway %s", command, gateway.id)},
			address:       gateway.address,
			canonicalName: gateway.name,
			aliases:       aliases,
		})
	}
	return &f
}

func (h *hosts) addIngress(ingress *networkingv1.Ingress) {
	id := getIngressID(ingress)
	className := getIngressClass(ingress)
	if className == "" {
		return
	}
	_, ok := h.controllers[className]
	if !ok {
		return
	}
	ingressAliases := map[string]struct{}{}
	for _, rule := range ingress.Spec.Rules {
		ingressAliases[rule.Host] = struct{}{}
	}
	h.controllers[className].aliases[id] = ingressAliases
}

func (h *hosts) removeIngress(ingress *networkingv1.Ingress) {
	id := getIngressID(ingress)
	className := getIngressClass(ingress)
	if className == "" {
		return
	}
	_, ok := h.controllers[className]
	if !ok {
		return
	}
	delete(h.controllers[className].aliases, id)
}

func (h *hosts) addVirtualService(vs *istio.VirtualService) {
	id := getVirtualServiceID(vs)
	gatewayID := getVirtualServiceGateway(vs)
	if gatewayID == "" {
		return
	}
	gwr, ok := h.gateways[gatewayID]
	if !ok {
		return
	}
	vsAliases := map[string]struct{}{}
	for _, host := range vs.Spec.Hosts {
		vsAliases[host] = struct{}{}
	}

	gwr.aliases[id] = vsAliases
	h.gateways[gatewayID] = gwr
}

func (h *hosts) removeVirtualService(vs *istio.VirtualService) {
	id := getVirtualServiceID(vs)
	gatewayID := getVirtualServiceGateway(vs)
	if gatewayID == "" {
		return
	}
	_, ok := h.gateways[gatewayID]
	if !ok {
		return
	}
	delete(h.gateways[gatewayID].aliases, id)
}

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := func() error {
			ctx := context.TODO()
			var defaultHosts *hostsFile
			initialHosts, err := loadHostsFile(etcHosts)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			backupHosts, err := loadHostsFile(backupEtcHosts)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			backupHostsExists := err == nil
			if !backupHostsExists {
				defaultHosts = initialHosts
			} else if ignoreBackupEtcHosts {
				defaultHosts = initialHosts
			} else {
				defaultHosts = backupHosts
			}

			err = os.MkdirAll(filepath.Dir(etcHosts), 0700)
			if err != nil {
				return err
			}

			// TODO: Configurable?
			resolver := net.Resolver{}
			controllerHosts := make(map[string]host, len(ingressClassMapping))
			// TODO: Record port, use port in dial
			for className, address := range ingressClassMapping {
				controllerURL, err := url.Parse(address)
				if err != nil {
					return err
				}
				klog.Infof("%#v", *controllerURL)
				hostname := controllerURL.Hostname()
				if hostname == "" {
					hostname = controllerURL.Path
				}
				addresses, err := resolver.LookupHost(ctx, hostname)
				if err != nil {
					return err
				}
				controllerHosts[className] = host{name: hostname, address: addresses[0]}
			}
			gatewayHosts := make(map[string]host, len(istioGatewayMapping))
			// TODO: Record port, use port in dial
			for gatewayID, address := range istioGatewayMapping {
				gatewayURL, err := url.Parse(address)
				if err != nil {
					return err
				}
				klog.Infof("%#v", *gatewayURL)
				hostname := gatewayURL.Hostname()
				if hostname == "" {
					hostname = gatewayURL.Path
				}
				addresses, err := resolver.LookupHost(ctx, hostname)
				if err != nil {
					return err
				}
				gatewayHosts[gatewayID] = host{name: hostname, address: addresses[0]}
			}

			err = defaultHosts.writeToFile(backupEtcHosts)
			if err != nil {
				return err
			}
			defer func() {
				err := defaultHosts.writeToFile(etcHosts)
				if err != nil {
					klog.Errorf("Failed to restore backup hosts file, backup located at %s: %s", backupEtcHosts, err)
				}
			}()
			loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
			kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &k8sOverrides)
			k8scfg, err := kubeConfig.ClientConfig()
			k8sclient, err := kubernetes.NewForConfig(k8scfg)
			if err != nil {
				return err
			}
			istioclient, err := istiocfg.NewForConfig(k8scfg)
			if err != nil {
				return err
			}

			hostsMap := defaultHosts.buildHosts(controllerHosts, gatewayHosts)

			defaultHosts.writeToFile(backupEtcHosts)
			defaultHosts.writeToFile(etcHosts)

			ingressInformerFactories := []k8sinformers.SharedInformerFactory{}
			ingressInformers := []networkingv1inf.IngressInformer{}

			vsInformerFactories := []istioinformers.SharedInformerFactory{}
			vsInformers := []istiov1a3inf.VirtualServiceInformer{}

			if allNamespaces {
				ingressInformerFactory := k8sinformers.NewSharedInformerFactory(k8sclient, time.Second*30)
				ingressInformer := ingressInformerFactory.Networking().V1().Ingresses()
				ingressInformerFactories = append(ingressInformerFactories, ingressInformerFactory)
				ingressInformers = append(ingressInformers, ingressInformer)
				if istioEnabled {

					vsInformerFactory := istioinformers.NewSharedInformerFactory(istioclient, time.Second*30)
					vsInformer := vsInformerFactory.Networking().V1alpha3().VirtualServices()
					vsInformerFactories = append(vsInformerFactories, vsInformerFactory)
					vsInformers = append(vsInformers, vsInformer)
				}
			} else {
				for _, ns := range namespaces {
					ingressInformerFactory := k8sinformers.NewSharedInformerFactoryWithOptions(k8sclient, time.Second*30, k8sinformers.WithNamespace(ns))
					ingressInformer := ingressInformerFactory.Networking().V1().Ingresses()
					ingressInformerFactories = append(ingressInformerFactories, ingressInformerFactory)
					ingressInformers = append(ingressInformers, ingressInformer)
					if istioEnabled {
						vsInformerFactory := istioinformers.NewSharedInformerFactoryWithOptions(istioclient, time.Second*30, istioinformers.WithNamespace(ns))
						vsInformer := vsInformerFactory.Networking().V1alpha3().VirtualServices()
						vsInformerFactories = append(vsInformerFactories, vsInformerFactory)
						vsInformers = append(vsInformers, vsInformer)
					}
				}
			}

			upsert := func(obj interface{}) {
				ingress, ok := obj.(*networkingv1.Ingress)
				if ok {
					hostsMap.addIngress(ingress)
					newHostsFile := hostsMap.buildHostsFile()
					err := newHostsFile.writeToFile(etcHosts)
					if err != nil {
						klog.Error(err)
						return
					}
					if klog.V(4).Enabled() {
						klog.V(4).Infof("Hosts: %#v", hostsMap)
						fileContents := strings.Builder{}
						newHostsFile.write(&fileContents)
						klog.V(4).Infof("New Hosts File:\n%s", fileContents.String())
					}
					return
				}
				vs, ok := obj.(*istio.VirtualService)
				if ok {
					hostsMap.addVirtualService(vs)
					newHostsFile := hostsMap.buildHostsFile()
					err := newHostsFile.writeToFile(etcHosts)
					if err != nil {
						klog.Error(err)
						return
					}
					if klog.V(4).Enabled() {
						klog.V(4).Infof("Hosts: %#v", hostsMap)
						fileContents := strings.Builder{}
						newHostsFile.write(&fileContents)
						klog.V(4).Infof("New Hosts File:\n%s", fileContents.String())
					}
					return
				}
			}

			remove := func(obj interface{}) {
				ingress, ok := obj.(*networkingv1.Ingress)
				if ok {
					hostsMap.removeIngress(ingress)

					newHostsFile := hostsMap.buildHostsFile()
					err := newHostsFile.writeToFile(etcHosts)
					if err != nil {
						klog.Error(err)
						return
					}
					if klog.V(4).Enabled() {
						klog.V(4).Infof("Hosts: %#v", hostsMap)
						fileContents := strings.Builder{}
						newHostsFile.write(&fileContents)
						klog.V(4).Infof("New Hosts File:\n%s", fileContents.String())
					}
				}

				vs, ok := obj.(*istio.VirtualService)
				if ok {
					hostsMap.removeVirtualService(vs)
					newHostsFile := hostsMap.buildHostsFile()
					err := newHostsFile.writeToFile(etcHosts)
					if err != nil {
						klog.Error(err)
						return
					}
					if klog.V(4).Enabled() {
						klog.V(4).Infof("Hosts: %#v", hostsMap)
						fileContents := strings.Builder{}
						newHostsFile.write(&fileContents)
						klog.V(4).Infof("New Hosts File:\n%s", fileContents.String())
					}
				}
			}

			for _, informer := range ingressInformers {
				informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
					AddFunc: func(obj interface{}) {
						klog.V(3).Infof("New ingress: %#v", obj)
						upsert(obj)
					},
					UpdateFunc: func(oldObj, newObj interface{}) {
						klog.V(3).Infof("Updated ingress: %#v", newObj)
						upsert(newObj)
					},
					DeleteFunc: func(obj interface{}) {
						klog.V(3).Infof("Removed ingress: %#v", obj)
						remove(obj)
					},
				})
			}
			for _, informer := range vsInformers {
				informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
					AddFunc: func(obj interface{}) {
						klog.V(3).Infof("New gateway: %#v", obj)
						upsert(obj)
					},
					UpdateFunc: func(oldObj, newObj interface{}) {
						klog.V(3).Infof("Updated gateway: %#v", newObj)
						upsert(newObj)
					},
					DeleteFunc: func(obj interface{}) {
						klog.V(3).Infof("Removed gateway: %#v", obj)
						remove(obj)
					},
				})
			}
			for _, factory := range ingressInformerFactories {
				factory.Start(wait.NeverStop)
				factory.WaitForCacheSync(wait.NeverStop)
			}
			for _, factory := range vsInformerFactories {
				factory.Start(wait.NeverStop)
				factory.WaitForCacheSync(wait.NeverStop)
			}

			proxy := goproxy.NewProxyHttpServer()
			if klog.V(verboseProxyDebugLevel).Enabled() {
				proxy.Verbose = true
			}
			errs := make(chan error)
			go func() {
				err := http.ListenAndServe(listenAddress, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					if req.Method == "GET" && req.URL.Path == "/healthz" {
						w.WriteHeader(http.StatusOK)
					} else {
						proxy.ServeHTTP(w, req)
					}
				}))

				if err != nil {
					errs <- err
				} else {
					errs <- fmt.Errorf("Proxy server stopped without error")
				}
			}()
			return <-errs
		}()
		if err != nil {
			klog.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)

	defaultKubeconfigPath := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if defaultKubeconfigPath == "" {
		userHome, err := os.UserHomeDir()
		if err == nil {
			defaultKubeconfigPath = filepath.Join(userHome, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
		}
	}

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// proxyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// proxyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	proxyCmd.Flags().StringVar(&etcHosts, "hosts-file", "/etc/hosts", "Hosts file to modify")
	proxyCmd.Flags().StringVar(&backupEtcHosts, "backup-hosts-file", "/etc/hosts.kube-ingress-proxy.bak", "Location to backup hosts file during running, and restore from before exiting")
	proxyCmd.Flags().BoolVar(&ignoreBackupEtcHosts, "ignore-backup-hosts-file", false, "If false, will check for the backup hosts file, and use that as the default set of hosts. If true, will use the hosts file as the default set of hosts, even if the backup exists, and will overwrite the backup with a new backup")
	proxyCmd.Flags().StringVar(&listenAddress, "listen", "0.0.0.0:8080", "Address and port to listen on")
	proxyCmd.Flags().StringToStringVar(&ingressClassMapping, "ingress-class-address", map[string]string{}, "Map ingress class names to addresses")
	proxyCmd.Flags().StringVar(&kubeconfigPath, clientcmd.RecommendedConfigPathFlag, defaultKubeconfigPath, "Path to kubeconfig")
	proxyCmd.Flags().BoolVar(&allNamespaces, "all-namespaces", true, "If true, watch ingresses in all namespaces")
	proxyCmd.Flags().StringArrayVar(&namespaces, "namespaces", []string{}, "Namespaces to watch ingresses in. Ignored if --all-namespaces=true")
	proxyCmd.Flags().BoolVar(&istioEnabled, "istio-enabled", false, "If true, watch for istio Gateways, and create records for all VirtualServices that use them")
	proxyCmd.Flags().StringToStringVar(&istioGatewayMapping, "istio-gateway-address", map[string]string{}, "Map gateway namespace/name IDs to addresses")
	clientcmd.BindOverrideFlags(&k8sOverrides, proxyCmd.Flags(), clientcmd.RecommendedConfigOverrideFlags(""))
	klogFlags = goflag.NewFlagSet("", goflag.PanicOnError)
	klog.InitFlags(klogFlags)
	proxyCmd.Flags().AddGoFlagSet(klogFlags)
}
