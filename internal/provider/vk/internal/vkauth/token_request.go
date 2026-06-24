package vkauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	neturl "net/url"

	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

var (
	chromeHeaderOrder = []string{
		"host",
		"content-length",
		"sec-ch-ua-platform",
		"accept-language",
		"sec-ch-ua",
		"content-type",
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
	firefoxHeaderOrder = []string{
		"host",
		"content-length",
		"user-agent",
		"content-type",
		"accept",
		"origin",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"priority",
	}
	pHeaderOrder = []string{":method", ":path", ":authority", ":scheme"}
)

// doRequest отправляет POST form-запрос по url через tls-клиент с браузерным
// профилем и десериализует JSON-тело ответа.
func (c *Client) doRequest(ctx context.Context, httpClient tlsclient.HttpClient, profile browserprofile.Profile, data, url string) (map[string]any, error) {
	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("parse request URL: %w", err)
	}
	domain := parsedURL.Hostname()

	req, err := fhttp.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return nil, err
	}
	req.Host = domain
	browserprofile.ApplyFhttp(req, profile)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://vk.com")
	req.Header.Set("Referer", "https://vk.com/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Priority", "u=1, i")

	if profile.SecChUa != "" {
		req.Header[fhttp.HeaderOrderKey] = chromeHeaderOrder
	} else {
		req.Header[fhttp.HeaderOrderKey] = firefoxHeaderOrder
	}
	req.Header[fhttp.PHeaderOrderKey] = pHeaderOrder

	httpResp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := httpResp.Body.Close(); closeErr != nil {
			c.log.Warnf("[VK Auth] close response body: %s", closeErr)
		}
	}()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}
