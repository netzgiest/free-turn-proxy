package vkauth

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"

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

func getAPIVersion(ctx context.Context, link string, httpClient tlsclient.HttpClient, profile browserprofile.Profile, logf func(format string, args ...any)) string {
	cachedAPIVersionMu.Lock()
	defer cachedAPIVersionMu.Unlock()

	if cachedAPIVersion != "" {
		return cachedAPIVersion
	}

	version, err := detectAPIVersion(ctx, link, httpClient, profile)
	if err != nil {
		if logf != nil {
			logf("[VK Auth] API version detection failed: %v, using fallback %s", err, defaultAPIVersion)
		}
		cachedAPIVersion = defaultAPIVersion
		return cachedAPIVersion
	}

	if logf != nil {
		logf("[VK Auth] Detected API version: %s", version)
	}
	cachedAPIVersion = version
	return cachedAPIVersion
}

func detectAPIVersion(ctx context.Context, link string, httpClient tlsclient.HttpClient, profile browserprofile.Profile) (string, error) {
	pageURL := fmt.Sprintf("https://vk.ru/call/join/%s", link)
	html, err := fetchPage(ctx, httpClient, profile, pageURL)
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
			return version, nil
		}
	}

	for _, m := range scripts {
		src := m[1]
		js, err := fetchPage(ctx, httpClient, profile, src)
		if err != nil {
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

func fetchPage(ctx context.Context, httpClient tlsclient.HttpClient, profile browserprofile.Profile, url string) (string, error) {
	req, err := fhttp.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	browserprofile.ApplyFhttp(req, profile)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://vk.com")
	req.Header.Set("Referer", "https://vk.com/")
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

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	return string(body), nil
}
