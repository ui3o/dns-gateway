package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type RuntimeConfig struct {
	DebugLevel       int
	HTTPSPort        int
	HTTPPort         int
	DNSPort          int
	FixIPReplyForDNS string
	OriginalDNSIP    string
	CertFile         string
	KeyFile          string
	ConfigPath       string
}

type RegexConfig struct {
	Regex         string
	Replace       string
	CompiledRegex *regexp.Regexp
}

type RouteConfig struct {
	RegexConfig
	Proxy     string
	Address   string
	Domains   []string
	Whitelist []string
	Timeout   int
	Headers   map[string]RegexConfig
}

func (p *RouteConfig) createHTTPClient(uri string) (*http.Client, *http.Client) {
	if p.Timeout == 0 {
		p.Timeout = 2
	}
	customTransport := &http.Transport{}
	client := &http.Client{
		Timeout:   time.Duration(p.Timeout) * time.Second,
		Transport: customTransport,
	}
	speedClient := &http.Client{
		Timeout:   500 * time.Microsecond,
		Transport: customTransport,
	}
	port := "80"
	if strings.HasPrefix(uri, "https://") {
		port = "443"
		customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h1"}}
	}
	if len(p.Address) == 0 {
		if u, err := url.Parse(uri); err != nil {
			logger("ERR", "Failed to parse URL for dial:", err)
		} else {
			p.Address = dnsRequestForIP(u, port)
		}
	} else {
		customTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, p.Address)
		}
	}
	return client, speedClient
}

func logRequestHeader(c *gin.Context) {
	if Config.DebugLevel > 1 {
		if err := c.Request.ParseForm(); err != nil {
			logger("ERR", "ParseForm request failed:", err)
		} else {
			logger("REQ", "Request Form is: ", c.Request.Form)
		}
		if err := c.Request.ParseMultipartForm(4096); err != nil {
			logger("ERR", "ParseMultipartForm request failed:", err)
		} else {
			logger("REQ", "Request MultipartForm is: ", c.Request.MultipartForm)
		}

		user, pass, hasAuth := c.Request.BasicAuth()
		if hasAuth {
			logger("REQ", "Request BasicAuth user:", user, "password:", pass)
		}
	}
}

func (p *RouteConfig) createHTTPRequest(url, targetHost string, c *gin.Context) (*http.Request, error) {
	c.Request.Body = p.logBody("Request", c.Request.Body)
	logRequestHeader(c)
	req, err := http.NewRequest(c.Request.Method, url, c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to create request: %v", err)
		return nil, err
	}
	req.Header = c.Request.Header.Clone()
	req.Header.Set("Host", targetHost)
	for k, v := range p.Headers {
		if v.CompiledRegex == nil {
			req.Header.Del(k)
		}
	}
	if Config.DebugLevel > 0 {
		for k, v := range req.Header {
			logger("REQ", "Forwarding header to backend:", k, ":", v)
		}
	}

	return req, nil
}

func (p *RouteConfig) logBody(target string, body io.ReadCloser) io.ReadCloser {
	if Config.DebugLevel > 1 && body != nil {
		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			logger("ERR", "Failed to read response body:", err)
		} else {
			logger("REQ", target, " body: ", string(bodyBytes))
			// Reset resp.Body so it can be copied to the client
			body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		}
	}
	return body
}

func (p *RouteConfig) serveHTTPRequest(url, targetHost string, c *gin.Context) {
	client, speedClient := p.createHTTPClient(url)
	logger("REQ", "Send a backend request:", url)
	req, err := p.createHTTPRequest(url, targetHost, c)
	if err != nil {
		return
	}
	if speedResp, err := speedClient.Do(req); err == nil {
		defer speedResp.Body.Close()
	}
	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		logger("ERR", "Failed to reach backend:", err)
		c.String(http.StatusBadGateway, "Failed to reach backend: %v", err)
		return
	}
	defer resp.Body.Close()

	// Copy all headers
	for k, v := range resp.Header {
		if Config.DebugLevel > 0 {
			logger("REQ", "Received header from backend:", k, ":", v)
		}
		for _, vv := range v {
			if k != "Connection" && k != "Keep-Alive" {
				c.Writer.Header().Add(k, strings.ReplaceAll(vv, c.Request.RemoteAddr, targetHost))
			}
		}
	}
	c.Status(resp.StatusCode)
	logger("REQ", "Received response code from backend:", resp.StatusCode)
	resp.Body = p.logBody("Response", resp.Body)
	// Copy body
	io.Copy(c.Writer, resp.Body)
}

func (p *RouteConfig) serveWebsocket(url, targetHost string, c *gin.Context) {
	// Handle WebSocket upgrade
	var secWebsocketProtocol = "sec-websocket-protocol"
	var err error
	host := targetHost
	reqHeader := http.Header{
		"Host": []string{host},
	}
	subProtocols := c.Request.Header.Get(secWebsocketProtocol)
	if len(subProtocols) > 0 {
		reqHeader[secWebsocketProtocol] = []string{subProtocols}
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	targetURL := "ws://" + host + c.Request.RequestURI
	backendConn, _, err := websocket.DefaultDialer.Dial(targetURL, reqHeader)
	if err != nil {
		logger("ERR", "Backend dial error:", err)
		return
	}
	defer backendConn.Close()

	// Upgrade client connection
	backendSubprotocol := backendConn.Subprotocol()
	logger("WS ", "backendSubprotocol", backendSubprotocol)
	var clientConn *websocket.Conn

	if len(backendSubprotocol) > 0 {
		clientConn, err = upgrader.Upgrade(c.Writer, c.Request, http.Header{
			secWebsocketProtocol: []string{backendSubprotocol},
		})
	} else {
		clientConn, err = upgrader.Upgrade(c.Writer, c.Request, nil)
	}
	if err != nil {
		logger("ERR", "Client upgrade error:", err)
		return
	}
	defer clientConn.Close()

	logger("WS ", "WebSocket proxy connected")
	proxyCopy := func(src, dst *websocket.Conn, errCh chan error) {
		for {
			msgType, msg, err := src.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			err = dst.WriteMessage(msgType, msg)
			if err != nil {
				errCh <- err
				return
			}
		}
	}
	// Proxy messages in both directions
	errCh := make(chan error, 2)
	go proxyCopy(clientConn, backendConn, errCh)
	go proxyCopy(backendConn, clientConn, errCh)
	<-errCh
}

func (p *RouteConfig) StartServeProxy(url, targetHost string, c *gin.Context) bool {
	c.Request.URL.Host = targetHost
	c.Request.Host = targetHost

	if strings.ToLower(c.Request.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(c.Request.Header.Get("Upgrade")) == "websocket" {
		p.serveWebsocket(url, targetHost, c)
	} else {
		p.serveHTTPRequest(url, targetHost, c)
	}
	return false
}

func HandleRequest(c *gin.Context) {
	found := false
	scheme := "http://"
	if c.Request.TLS != nil {
		scheme = "https://"
	}
	sourceUrl := scheme + c.Request.Host + c.Request.RequestURI

	for k, route := range AllRoutes { // posible to add regex match here
		targetUrl := route.CompiledRegex.ReplaceAllString(sourceUrl, route.Replace)
		targetHost := strings.Split(strings.Split(targetUrl, "://")[1], c.Request.RequestURI)[0]
		if route.CompiledRegex.FindString(sourceUrl) != "" {
			found = true
			logger("REQ", "HandleRequest found route for id:", k)
			if AllRoutes[k].Proxy != "" {
				AllRoutes[k].serveHTTPRequestViaProxy(targetUrl, targetHost, AllRoutes[k].Proxy, c)
				return
			}
			AllRoutes[k].StartServeProxy(targetUrl, targetHost, c)
			return
		}
	}
	if !found {
		logger(red("ERR"), "HandleRequest no route found for: ", sourceUrl)
		c.String(http.StatusBadGateway, "Failed to reach backend")
	}
}

func HandleCONNECT(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		logger("ERR", "Hijack failed:", err)
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	// Respond to the CONNECT request with a successful tunnel establishment
	fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Establish a connection to the target server

	targetConn, err := net.Dial("tcp", "localhost:"+fmt.Sprintf("%d", Config.HTTPSPort))
	if err != nil {
		logger("ERR", "Failed to connect to target:", err)
		return
	}
	defer targetConn.Close()

	// Start proxying data between the client and the target server
	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)
}

func (p *RouteConfig) createProxiedHTTPClient(proxyAddr string) *http.Client {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		logger("ERR", "Failed to parse proxy address:", err)
		return http.DefaultClient
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	if strings.HasPrefix(proxyAddr, "https") {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(p.Timeout) * time.Second,
	}
}

// Usage: p.serveHTTPRequestViaProxy(url, targetHost, proxyAddr, c)
func (p *RouteConfig) serveHTTPRequestViaProxy(url, targetHost, proxyAddr string, c *gin.Context) {
	client := p.createProxiedHTTPClient(proxyAddr)
	logger("REQ", "Send a backend request via proxy:", url, "proxy:", proxyAddr)
	req, err := p.createHTTPRequest(url, targetHost, c)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		logger("ERR", "Failed to reach backend via proxy:", err)
		c.String(http.StatusBadGateway, "Failed to reach backend via proxy: %v", err)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		for _, vv := range v {
			if k != "Connection" && k != "Keep-Alive" {
				c.Writer.Header().Add(k, strings.ReplaceAll(vv, c.Request.RemoteAddr, targetHost))
			}
		}
	}
	c.Status(resp.StatusCode)
	resp.Body = p.logBody("Response", resp.Body)
	io.Copy(c.Writer, resp.Body)
}
