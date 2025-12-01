package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"go.senan.xyz/flagconf"
)

const (
	DNS_GEATEWAY_CONFIG = "/etc/dns-gateway/conf"
	CERT_DIR            = "/etc/dns-gateway/certs"
	CERT_CONFIG         = CERT_DIR + "/config"
	CERT_SAN            = CERT_CONFIG + "/san.cnf"
	CERT_CA             = CERT_DIR + "/cacerts/ca.crt"
	CERT_CA_KEYSTORE    = CERT_DIR + "/cacerts/keystore.jks"
	SERVER_CRT          = CERT_DIR + "/certs/server/server.crt"
	SERVER_KEY          = CERT_DIR + "/certs/server/server.key"
)

var (
	AllRoutes = make(map[string]*RouteConfig)
	AllDoamin = make(map[string][]string)
	Config    = RuntimeConfig{}
)

var (
	TermColorReset  = "\033[0m"
	TermColorRed    = "\033[31m"
	TermColorGreen  = "\033[32m"
	TermColorBlue   = "\033[34m"
	TermColorYellow = "\033[33m"
)

func yellow(s string) string {
	return TermColorYellow + s + TermColorReset
}
func red(s string) string {
	return TermColorRed + s + TermColorReset
}

func blue(s string) string {
	return TermColorBlue + s + TermColorReset
}

func green(s string) string {
	return TermColorGreen + s + TermColorReset
}

func logger(title string, v ...any) {
	var loggerMu sync.Mutex
	loggerMu.Lock()
	defer loggerMu.Unlock()
	fmt.Printf("[%s] %s | ",
		title,
		time.Now().Format("2006/01/02 - 15:04:05"),
	)
	for _, val := range v {
		fmt.Print(val)
	}
	fmt.Print("\n")
}

func dnsRequestForIP(url *url.URL, port string) string {
	urlBase := strings.Split(url.Host, ":")
	if len(urlBase) > 1 {
		port = urlBase[1]
	}
	u := urlBase[0]
	dnsMsg := new(dns.Msg)
	dnsMsg.SetQuestion(dns.Fqdn(u), dns.TypeA)
	c := new(dns.Client)
	resp, _, err := c.Exchange(dnsMsg, Config.OriginalDNSIP+":53")
	if err != nil {
		logger(red("ERR"), "DNS query for ", u, " failed: ", err)
	} else {
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				addr := a.A.String() + ":" + port
				logger("DNS", "DNS query for ", u, ": ", addr)
				return addr
			}
		}
	}
	return ""
}

func initAllDomians(conf map[string]*RouteConfig) {
	for _, route := range conf {
		for _, d := range route.Domains {
			AllDoamin[d+"."] = slices.Concat(AllDoamin[d+"."], route.Whitelist)
		}
	}
	maps.Copy(AllRoutes, conf)
}

func loadConfigs() {
	files, err := os.ReadDir(Config.ConfigPath)
	if err != nil {
		log.Fatalf(red("ERR"), "Failed to read config directory: %v", err)
	}
	for _, file := range files {
		if !file.IsDir() && regexp.MustCompile(`\.json$`).MatchString(file.Name()) {
			fullPath := Config.ConfigPath + string(os.PathSeparator) + file.Name()
			logger("INI", "Found JSON config file:", fullPath)
			routesData, err := os.ReadFile(fullPath)
			if err != nil {
				log.Fatalf(red("ERR"), "Failed to read routes.json: %v", err)
			}
			var conf map[string]*RouteConfig
			if err := json.Unmarshal(routesData, &conf); err != nil {
				log.Fatalf(red("ERR"), "Failed to parse routes.json: %v", err)
			}
			initAllDomians(conf)
		}
	}
}

func generateCerts() {

	runCmd := func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		cmd.Dir = CERT_CONFIG
		output, err := cmd.CombinedOutput()
		if err != nil {
			logger(red("ERR"), "Command failed:", string(output))
		}
		return err
	}
	runCmd("make", "gen_ca_cert")

	if err := importCAIntoJKS(CERT_CA, CERT_CA_KEYSTORE, "dns-gateway", "changeit"); err != nil {
		log.Fatalf(red("ERR"), "Failed to start import ca-cert into keystore.jks: %v", err)
	}

	if generateNeed, err := compareDNAndAltNames(SERVER_CRT, CERT_SAN); err != nil {
		logger(yellow("WRN"), "Failed to read server.crt or san.cnf: %v. Run make gen_server_cert", err)
		runCmd("make", "gen_server_cert")
	} else if !generateNeed {
		logger("INI", "No need to generate new server certificate")
		return
	} else {
		runCmd("make", "gen_server_cert")
		logger("INI", "Generating new server certificate")
	}
}

func init() {
	flag.CommandLine.Init("env_param_dns_gateway", flag.ExitOnError)

	flag.IntVar(&Config.DebugLevel, "debug", 0, "Enable debug mode")
	flag.IntVar(&Config.HTTPSPort, "https_port", 443, "Default: 443")
	flag.IntVar(&Config.DNSPort, "dns_port", 53, "Default: 53")
	flag.IntVar(&Config.HTTPPort, "http_port", 80, "Default: 80")

	flag.StringVar(&Config.KeyFile, "server_key", SERVER_KEY, SERVER_KEY)
	flag.StringVar(&Config.CertFile, "server_cert", SERVER_CRT, SERVER_CRT)
	flag.StringVar(&Config.ConfigPath, "configpath", DNS_GEATEWAY_CONFIG, "")
	flag.StringVar(&Config.FixIPReplyForDNS, "fix_ip_reply_for_dns", "", "")
	flag.StringVar(&Config.OriginalDNSIP, "original_dns_ip", "", "")

	flag.Parse()
	flagconf.ParseEnv()

	if confJson, err := json.MarshalIndent(Config, "", "  "); err != nil {
		logger(red("ERR"), "Failed to marshal config to JSON:", err)
	} else {
		logger("INI", "RuntimeConfig JSON:", string(confJson))
	}
	generateCerts()
	loadConfigs()
	for name, route := range AllRoutes {
		compiled := regexp.MustCompile(route.Regex)
		AllRoutes[name].CompiledRegex = compiled
		for hk, hv := range route.Headers {
			if hv.Regex != "" {
				hCompiled := regexp.MustCompile(hv.Regex)
				h := AllRoutes[name].Headers[hk]
				h.CompiledRegex = hCompiled
				AllRoutes[name].Headers[hk] = h
			}
		}
	}
}

func findIP(addrs []net.Addr, subnet string) (ip string) {
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			if regexp.MustCompile(subnet).MatchString(ipnet.IP.String()) {
				if Config.DebugLevel > 0 {
					logger("DNS", "Matched subnet: ", subnet, " with IP: ", ipnet.IP.String())
				}
				ip = ipnet.IP.String()
				break
			}
		}
	}
	return ip
}

func findIPForDNSandOriginalDns(w dns.ResponseWriter) (remoteNames []string, fixIPReplyForDNS string, originalDNSIp string) {
	remoteAddr := w.RemoteAddr().String()
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	fixIPReplyForDNS = ip
	subnet := strings.Join(strings.Split(ip, ".")[:3], ".")
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		logger(red("ERR"), "Failed to get interface addresses:", err)
	}
	if err == nil {
		fixIPReplyForDNS = findIP(addrs, subnet)
	}
	if Config.FixIPReplyForDNS != "" {
		fixIPReplyForDNS = Config.FixIPReplyForDNS
	}
	dnsIP := subnet + ".1"
	if Config.OriginalDNSIP != "" {
		dnsIP = Config.OriginalDNSIP
	}
	names, err := net.LookupAddr(ip)
	if err != nil {
		logger(red("ERR"), "Reverse lookup failed:", err)
	}
	return names, fixIPReplyForDNS, dnsIP
}

func needToHandleDNSOverride(domain string, remoteNames []string) bool {
	if r, exists := AllDoamin[domain]; exists {
		for _, rn := range remoteNames {
			if slices.Contains(r, rn) {
				return true
			}
		}
		return len(r) == 0
	}
	return false
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if Config.DebugLevel > 0 {
		logger("DNS", "[REQ_START] Handle DNS request => |", r.Question, "|")
	}
	override := false
	msg := dns.Msg{}
	msg.SetReply(r)

	remoteNames, fixIPReplyForDNS, dnsIP := findIPForDNSandOriginalDns(w)

	for _, q := range r.Question {
		if q.Qtype == dns.TypeA {
			if needToHandleDNSOverride(q.Name, remoteNames) {
				if Config.DebugLevel < 1 {
					logger("DNS", "[REQ_START] Handle DNS request => |", r.Question, "|")
				}
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP(fixIPReplyForDNS),
				}
				msg.Answer = append(msg.Answer, rr)
				override = true
			}
		}

	}
	if !override {
		c := new(dns.Client)
		resp, _, err := c.Exchange(r, dnsIP+":53")
		if err != nil {
			logger(red("ERR"), "Failed to forward DNS request:", err)
		} else {
			msg = *resp
		}
	}
	w.WriteMsg(&msg)
}

func main() {
	go func() {
		dns.HandleFunc(".", handleDNSRequest)
		server := &dns.Server{Addr: fmt.Sprintf(":%d", Config.DNSPort), Net: "udp"}
		logger("DNS", "Starting DNS server on :", Config.DNSPort)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf(red("ERR"), "Failed to start DNS server: %v", err)
		}
	}()

	proxyHandler := func(c *gin.Context) {
		if c.Request.Method == http.MethodConnect {
			HandleCONNECT(c.Writer, c.Request)
		} else {
			HandleRequest(c)
		}

	}
	rHTTP := gin.Default()
	rHTTP.NoRoute(func(c *gin.Context) {
		scheme := "http://"
		if c.Request.TLS != nil {
			scheme = "https://"
		}
		sourceUrl := scheme + c.Request.Host + c.Request.RequestURI
		logger(blue("HTP"), "[REQ_START] Handle request => |", c.Request.Method, "|", sourceUrl, "|")
		proxyHandler(c)
	})

	rHTTPS := gin.Default(func(e *gin.Engine) { e.UseH2C = false })
	rHTTPS.NoRoute(func(c *gin.Context) {
		scheme := "http://"
		if c.Request.TLS != nil {
			scheme = "https://"
		}
		sourceUrl := scheme + c.Request.Host + c.Request.RequestURI
		logger(green("HTS"), "[REQ_START] Handle request => |", c.Request.Method, "|", sourceUrl, "|")
		proxyHandler(c)
	})

	go func() {
		logger("INI", "Gin start in http mode on port :", Config.HTTPPort)
		rHTTP.Run(fmt.Sprintf(":%d", Config.HTTPPort))
	}()
	if len(Config.CertFile) > 0 && len(Config.KeyFile) > 0 {
		logger("INI", "Gin start in https mode on port :", Config.HTTPSPort)
		server := &http.Server{
			Addr:         fmt.Sprintf(":%d", Config.HTTPSPort),
			Handler:      rHTTPS.Handler(),
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, // Disable HTTP/2 over TLS
		}
		if err := server.ListenAndServeTLS(Config.CertFile, Config.KeyFile); err != nil {
			log.Fatalf(red("ERR"), "Failed to start HTTPS server: %v", err)
		}
	}
}
