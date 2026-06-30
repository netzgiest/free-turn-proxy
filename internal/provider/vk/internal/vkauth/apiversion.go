package vkauth

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"

	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"
)

const defaultAPIVersion = "5.282"

var (
	cachedAPIVersion   string
	cachedAPIVersionMu sync.Mutex
	reScriptSrc        = regexp.MustCompile(`<script[^>]+src="([^"]+)"[^>]*>`)
	reJSAPIVersion     = regexp.MustCompile(`api[Vv]ersion[":=]\s*"(\d+\.\d{3})"`)
	reURLVersion       = regexp.MustCompile(`[?&]v=(\d+\.\d{3})(?:&|")`)
)

var (
	// Firefox не шлёт sec-ch-ua*, порядок псевдо-заголовков един для всех браузеров.
	firefoxFetchHeaderOrder = []string{
		"host",
		"user-agent",
		"accept",
		"origin",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"priority",
	}
	chromeFetchHeaderOrder = []string{
		"host",
		"sec-ch-ua-platform",
		"accept-language",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"user-agent",
		"accept",
		"origin",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"priority",
	}
	fetchPHeaderOrder = []string{":method", ":path", ":authority", ":scheme"}
)

func getAPIVersion(ctx context.Context, link string, httpClient tlsclient.HttpClient, profile browserprofile.Profile, dom domainSet, log logx.Logger) string {
	cachedAPIVersionMu.Lock()
	defer cachedAPIVersionMu.Unlock()

	if cachedAPIVersion != "" {
		return cachedAPIVersion
	}

	version, err := detectAPIVersion(ctx, link, httpClient, profile, dom, log)
	if err != nil {
		if log != nil {
			log.Infof("[VK Auth] API version detection failed: %v, using fallback %s", err, defaultAPIVersion)
		}
		cachedAPIVersion = defaultAPIVersion
		return cachedAPIVersion
	}

	if log != nil {
		log.Infof("[VK Auth] Detected API version: %s", version)
	}
	cachedAPIVersion = version
	return cachedAPIVersion
}

func detectAPIVersion(ctx context.Context, link string, httpClient tlsclient.HttpClient, profile browserprofile.Profile, dom domainSet, log logx.Logger) (string, error) {
	pageURL := fmt.Sprintf("https://"+dom.WebDomain+"/call/join/%s", link)
	html, err := fetchPage(ctx, httpClient, profile, pageURL, dom, log)
	if err != nil {
		return "", fmt.Errorf("fetch page: %w", err)
	}

	scripts := reScriptSrc.FindAllStringSubmatch(html, -1)
	if len(scripts) == 0 {
		return "", fmt.Errorf("no script tags found")
	}

	for _, m := range scripts {
		src := m[1]
		if version := extractVersionFromURL(src); version != "" {
			if log != nil && log.DebugEnabled() {
				log.Debugf("[VK Auth] API version found in URL: %s", version)
			}
			return version, nil
		}
	}

	for _, m := range scripts {
		src := m[1]
		js, err := fetchPage(ctx, httpClient, profile, src, dom, log)
		if err != nil {
			if log != nil && log.DebugEnabled() {
				log.Debugf("[VK Auth] Failed to fetch script %s: %v", src, err)
			}
			continue
		}
		if ms := reJSAPIVersion.FindStringSubmatch(js); ms != nil {
			return ms[1], nil
		}
		if ms := reURLVersion.FindStringSubmatch(js); ms != nil {
			return ms[1], nil
		}
	}

	return "", fmt.Errorf("API version not found in any script")
}

func extractVersionFromURL(url string) string {
	if ms := reURLVersion.FindStringSubmatch(url); ms != nil {
		return ms[1]
	}
	return ""
}

func fetchPage(ctx context.Context, httpClient tlsclient.HttpClient, profile browserprofile.Profile, url string, dom domainSet, log logx.Logger) (string, error) {
	req, err := fhttp.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	browserprofile.ApplyFhttp(req, profile)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://"+dom.WebDomain)
	req.Header.Set("Referer", "https://"+dom.WebDomain+"/")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Priority", "u=1")

	if profile.SecChUa != "" {
		req.Header[fhttp.HeaderOrderKey] = chromeFetchHeaderOrder
	} else {
		req.Header[fhttp.HeaderOrderKey] = firefoxFetchHeaderOrder
	}
	req.Header[fhttp.PHeaderOrderKey] = fetchPHeaderOrder

	if log != nil && log.DebugEnabled() {
		log.Debugf("[VK Auth] >>> GET %s", url)
	}
	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	elapsed := time.Since(start)
	if log != nil && log.DebugEnabled() {
		log.Debugf("[VK Auth] <<< GET %s (%dms) status=%d", url, elapsed.Milliseconds(), resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	return string(body), nil
}
