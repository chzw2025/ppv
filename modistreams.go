package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"encoding/json"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// ============ 配置 ============

type Config struct {
	Port           int
	MaxConcurrent  int
	ExtractTimeout time.Duration
	FetchTimeout   time.Duration
	CacheTTL       time.Duration
	CleanupInterval time.Duration
}

// ============ 端口自行配置 ============

var config = Config{
	Port:           11458,  //自定义端口
	MaxConcurrent:  5,
	ExtractTimeout: 20 * time.Second,
	FetchTimeout:   10 * time.Second,
	CacheTTL:       1 * time.Hour,
	CleanupInterval: 10 * time.Minute,
}

// ============ 全局状态 ============

type CacheEntry struct {
	URL  string
	Time time.Time
}

var (
	m3u8Cache    = make(map[string]*CacheEntry)
	cacheMu      sync.RWMutex
	activePages  int32
	activePagesMu sync.Mutex
	totalRequests int64
	browserCtx    context.Context
	browserCancel context.CancelFunc
	browserMu     sync.Mutex
	tlsClient     tls_client.HttpClient
	tlsClientMu   sync.Mutex
)

func logMsg(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), msg)
}

// ============ TLS Client (绕 TLS 指纹) ============

func getTLSClient() (tls_client.HttpClient, error) {
	tlsClientMu.Lock()
	defer tlsClientMu.Unlock()

	if tlsClient != nil {
		return tlsClient, nil
	}

	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(int(config.FetchTimeout.Seconds())),
		tls_client.WithClientProfile(profiles.Chrome_120),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar),
		tls_client.WithInsecureSkipVerify(),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return nil, err
	}

	tlsClient = client
	return tlsClient, nil
}

func resetTLSClient() {
	tlsClientMu.Lock()
	defer tlsClientMu.Unlock()
	tlsClient = nil
}

// ============ 浏览器管理 ============

func initBrowser() error {
	browserMu.Lock()
	defer browserMu.Unlock()

	if browserCtx != nil {
		return nil
	}

	logMsg("启动浏览器...")

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)

	// 启动浏览器
	if err := chromedp.Run(ctx); err != nil {
		allocCancel()
		cancel()
		return fmt.Errorf("启动浏览器失败: %w", err)
	}

	browserCtx = ctx
	browserCancel = func() {
		cancel()
		allocCancel()
	}

	logMsg("✓ 浏览器已就绪")
	return nil
}

func closeBrowser() {
	browserMu.Lock()
	defer browserMu.Unlock()

	if browserCancel != nil {
		logMsg("关闭浏览器...")
		browserCancel()
		browserCtx = nil
		browserCancel = nil
	}
}

func restartBrowser() error {
	closeBrowser()
	return initBrowser()
}

// ============ 提取 m3u8 地址 ============

func extractM3u8(uriName string) (string, bool, error) {
	// 检查缓存
	cacheMu.RLock()
	if entry, ok := m3u8Cache[uriName]; ok && time.Since(entry.Time) < config.CacheTTL {
		cacheMu.RUnlock()
		logMsg("地址缓存命中: %s", uriName)
		return entry.URL, true, nil
	}
	cacheMu.RUnlock()

	// 并发控制
	activePagesMu.Lock()
	if int(activePages) >= config.MaxConcurrent {
		activePagesMu.Unlock()
		return "", false, fmt.Errorf("too many concurrent requests")
	}
	activePages++
	activePagesMu.Unlock()
	defer func() {
		activePagesMu.Lock()
		activePages--
		activePagesMu.Unlock()
	}()

	// 确保浏览器就绪
	if err := initBrowser(); err != nil {
		return "", false, err
	}

	browserMu.Lock()
	ctx := browserCtx
	browserMu.Unlock()

	if ctx == nil {
		return "", false, fmt.Errorf("browser not available")
	}

	// 创建新 tab
	tabCtx, tabCancel := chromedp.NewContext(ctx)
	defer tabCancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(tabCtx, config.ExtractTimeout)
	defer timeoutCancel()

	embedURL := fmt.Sprintf("https://modistreams.org/embed/%s", uriName)
	logMsg("访问: %s", embedURL)

	var m3u8URL string
	m3u8Found := make(chan string, 1)

	// 监听网络请求
	chromedp.ListenTarget(timeoutCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			u := e.Response.URL
			if strings.Contains(u, ".m3u8") && strings.Contains(u, "poocloud.in") {
				select {
				case m3u8Found <- u:
				default:
				}
			}
		case *fetch.EventRequestPaused:
			go func() {
				resType := e.ResourceType
				if resType == network.ResourceTypeImage ||
					resType == network.ResourceTypeFont ||
					resType == network.ResourceTypeStylesheet ||
					resType == network.ResourceTypeMedia {
					_ = chromedp.Run(timeoutCtx, fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient))
				} else {
					_ = chromedp.Run(timeoutCtx, fetch.ContinueRequest(e.RequestID))
				}
			}()
		}
	})

	// 启用网络监听和请求拦截
	err := chromedp.Run(timeoutCtx,
		network.Enable(),
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{
			{URLPattern: "*", RequestStage: fetch.RequestStageRequest},
		}),
		chromedp.Navigate(embedURL),
	)
	if err != nil {
		if strings.Contains(err.Error(), "context canceled") || strings.Contains(err.Error(), "target closed") {
			_ = restartBrowser()
		}
		return "", false, fmt.Errorf("navigate failed: %w", err)
	}

	// 等待 m3u8 URL
	select {
	case u := <-m3u8Found:
		m3u8URL = u
	case <-time.After(config.ExtractTimeout - 2*time.Second):
		// 超时，尝试从 video 元素获取
		var videoSrc string
		_ = chromedp.Run(timeoutCtx, chromedp.Evaluate(`
			(function() {
				var v = document.querySelector('video');
				if (v && v.src && v.src.includes('m3u8')) return v.src;
				var s = document.querySelector('video source');
				if (s && s.src && s.src.includes('m3u8')) return s.src;
				return '';
			})()
		`, &videoSrc))
		if videoSrc != "" {
			m3u8URL = videoSrc
		}
	}

	if m3u8URL == "" {
		return "", false, fmt.Errorf("m3u8 not found")
	}

	// 缓存
	cacheMu.Lock()
	m3u8Cache[uriName] = &CacheEntry{URL: m3u8URL, Time: time.Now()}
	cacheMu.Unlock()

	logMsg("提取成功: %s → %s", uriName, m3u8URL)
	return m3u8URL, false, nil
}

// ============ 通过 TLS Client 获取 m3u8 内容 ============

func fetchM3u8Content(targetURL string) (string, int, error) {
	client, err := getTLSClient()
	if err != nil {
		return "", 500, fmt.Errorf("TLS client error: %w", err)
	}

	req, err := fhttp.NewRequest(fhttp.MethodGet, targetURL, nil)
	if err != nil {
		return "", 500, err
	}

	req.Header.Set("Referer", "https://modistreams.org/")
	req.Header.Set("Origin", "https://modistreams.org")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		logMsg("TLS请求失败，重置client: %s", err)
		resetTLSClient()
		return "", 502, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 502, err
	}

	return string(body), resp.StatusCode, nil
}

// ============ 改写 m3u8 ============

var (
	reAbsM3u8 = regexp.MustCompile(`https://([a-z]+)\.poocloud\.in/([^\s]+\.m3u8)`)
	reRelM3u8 = regexp.MustCompile(`(?m)^([a-zA-Z0-9_\-\./]+\.m3u8)$`)
	// 匹配所有切片 URL：非 .m3u8 结尾的 https 链接
	reTS = regexp.MustCompile(`(?m)^(https://([a-zA-Z0-9.\-]+)/[^\s]+)$`)
)

func rewriteM3u8(text, targetURL, baseURL string, proxyTs bool) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return text
	}

	subdomain := strings.Split(u.Hostname(), ".")[0]
	pathParts := strings.Split(u.Path, "/")
	if len(pathParts) > 0 {
		pathParts = pathParts[:len(pathParts)-1]
	}
	basePath := strings.Join(pathParts, "/")

	suffix := ""
	if proxyTs {
		suffix = "?mode=proxy"
	}

	// 绝对路径 m3u8
	text = reAbsM3u8.ReplaceAllString(text, baseURL+"/proxy/$1/$2"+suffix)

	// 相对路径 m3u8
	text = reRelM3u8.ReplaceAllString(text,
		baseURL+"/proxy/"+subdomain+basePath+"/$1"+suffix)

	// ts 切片 - 排除 m3u8 和已改写的 URL，其余都代理
	if proxyTs {
		text = reTS.ReplaceAllStringFunc(text, func(match string) string {
			// 跳过 m3u8 文件
			if strings.HasSuffix(match, ".m3u8") || strings.Contains(match, ".m3u8?") {
				return match
			}
			// 跳过已改写的 URL（包含 /proxy/ 或 /ts/）
			if strings.Contains(match, "/proxy/") || strings.Contains(match, "/ts/") {
				return match
			}
			// 解析并改写
			parsed, err := url.Parse(match)
			if err != nil {
				return match
			}
			return fmt.Sprintf("%s/ts/%s%s", baseURL, parsed.Host, parsed.RequestURI())
		})
	}

	return text
}

// ============ 缓存清理 ============

func cacheCleanupLoop() {
	ticker := time.NewTicker(config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		cacheMu.Lock()
		expired := 0
		for k, v := range m3u8Cache {
			if now.Sub(v.Time) > config.CacheTTL {
				delete(m3u8Cache, k)
				expired++
			}
		}
		cacheMu.Unlock()
		if expired > 0 {
			logMsg("清理 %d 条过期缓存，剩余 %d", expired, len(m3u8Cache))
		}
	}
}

// ============ HTTP 处理 ============

func getBaseURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Header.Get("Host")
	}
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func m3u8Response(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(text))
}

func handleM3u8(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.Query().Get("uri")
	if uri == "" {
		jsonResponse(w, map[string]interface{}{"success": false, "error": "Missing uri"})
		return
	}

	logMsg("获取m3u8: %s", uri)
	m3u8URL, cached, err := extractM3u8(uri)
	if err != nil {
		logMsg("失败: %s", err)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	logMsg("结果: %s(缓存=%v) %s", uri, cached, m3u8URL)
	jsonResponse(w, map[string]interface{}{
		"success": true,
		"m3u8":    m3u8URL,
		"cached":  cached,
	})
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	// 解析 /proxy/{subdomain}/{path}
	path := strings.TrimPrefix(r.URL.Path, "/proxy/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		http.Error(w, "Invalid proxy path", 400)
		return
	}

	subdomain := parts[0]
	remotePath := parts[1]
	targetURL := fmt.Sprintf("https://%s.poocloud.in/%s", subdomain, remotePath)

	logMsg("代理m3u8: %s", targetURL)

	text, status, err := fetchM3u8Content(targetURL)
	if err != nil || status != 200 {
		logMsg("代理失败: status=%d err=%v", status, err)
		if status == 0 {
			status = 502
		}
		http.Error(w, "Proxy failed", status)
		return
	}

	proxyTs := r.URL.Query().Get("mode") == "proxy"
	baseURL := getBaseURL(r)
	rewritten := rewriteM3u8(text, targetURL, baseURL, proxyTs)

	m3u8Response(w, rewritten)
}

func handleStream(w http.ResponseWriter, r *http.Request, proxyTs bool) {
	uri := r.URL.Query().Get("uri")
	if uri == "" {
		http.Error(w, "Missing uri", 400)
		return
	}

	mode := "直连CDN"
	if proxyTs {
		mode = "代理ts"
	}
	logMsg("Stream(%s): %s", mode, uri)
	totalRequests++

	m3u8URL, _, err := extractM3u8(uri)
	if err != nil || m3u8URL == "" {
		errMsg := "M3U8 not found"
		if err != nil {
			errMsg = err.Error()
		}
		http.Error(w, errMsg, 404)
		return
	}

	text, status, err := fetchM3u8Content(m3u8URL)
	if err != nil || status != 200 {
		http.Error(w, "Failed to fetch m3u8", 502)
		return
	}

	baseURL := getBaseURL(r)
	rewritten := rewriteM3u8(text, m3u8URL, baseURL, proxyTs)

	m3u8Response(w, rewritten)
}

func handlePlay(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.Query().Get("uri")
	if uri == "" {
		http.Error(w, "Missing uri", 400)
		return
	}

	m3u8URL, _, err := extractM3u8(uri)
	if err != nil || m3u8URL == "" {
		http.Error(w, "M3U8 not found", 404)
		return
	}

	baseURL := getBaseURL(r)
	proxyURL := reAbsM3u8.ReplaceAllString(m3u8URL, baseURL+"/proxy/$1/$2")

	http.Redirect(w, r, proxyURL, http.StatusFound)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	cacheMu.RLock()
	cacheSize := len(m3u8Cache)
	cacheMu.RUnlock()

	activePagesMu.Lock()
	ap := activePages
	activePagesMu.Unlock()

	browserMu.Lock()
	browserStatus := "not started"
	if browserCtx != nil {
		browserStatus = "running"
	}
	browserMu.Unlock()

	jsonResponse(w, map[string]interface{}{
		"status":        "running",
		"architecture":  "go (chromedp + tls-client)",
		"port":          config.Port,
		"totalRequests":  totalRequests,
		"activePages":   ap,
		"maxConcurrent": config.MaxConcurrent,
		"urlCacheSize":  cacheSize,
		"browser":       browserStatus,
		"endpoints": map[string]string{
			"/stream?uri=":  "ts直连CDN",
			"/stream2?uri=": "ts经Nginx透传",
		},
	})
}

func handleClearCache(w http.ResponseWriter, r *http.Request) {
	cacheMu.Lock()
	m3u8Cache = make(map[string]*CacheEntry)
	cacheMu.Unlock()
	jsonResponse(w, map[string]interface{}{"success": true})
}

func handleRestart(w http.ResponseWriter, r *http.Request) {
	err := restartBrowser()
	if err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	jsonResponse(w, map[string]interface{}{"success": true})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

// ============ 主函数 ============

func main() {
	// 检查端口环境变量
	if p := os.Getenv("PORT"); p != "" {
		fmt.Sscanf(p, "%d", &config.Port)
	}

	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("Modistreams 代理服务 (Go)")
	fmt.Println("  单文件部署: chromedp + tls-client")
	fmt.Println("  /stream?uri=   → ts直连CDN")
	fmt.Println("  /stream2?uri=  → ts经Nginx透传")
	fmt.Println(strings.Repeat("=", 50))

	// 预启动浏览器
	if err := initBrowser(); err != nil {
		logMsg("⚠ 浏览器启动失败: %s", err)
		logMsg("  首次请求时会自动重试")
	}

	// 缓存清理
	go cacheCleanupLoop()

	// 路由
	mux := http.NewServeMux()
	mux.HandleFunc("/m3u8", handleM3u8)
	mux.HandleFunc("/proxy/", handleProxy)
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		handleStream(w, r, false)
	})
	mux.HandleFunc("/stream2", func(w http.ResponseWriter, r *http.Request) {
		handleStream(w, r, true)
	})
	mux.HandleFunc("/play", handlePlay)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/status", handleStatus)
	mux.HandleFunc("/clear-cache", handleClearCache)
	mux.HandleFunc("/restart", handleRestart)

	// 优雅关闭
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: mux,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logMsg("收到退出信号，正在清理...")
		closeBrowser()
		srv.Shutdown(context.Background())
	}()

	logMsg("✓ 服务就绪: http://0.0.0.0:%d", config.Port)

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
