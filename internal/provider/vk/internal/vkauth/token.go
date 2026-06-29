package vkauth

import (
	"context"
	"fmt"
	neturl "net/url"
	"strings"

	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/namegen"

	tlsclient "github.com/bogdanfinn/tls-client"
)

// getTokenChain выполняет 4-шаговый обмен токенами VK для одной пары client_id/secret
// и возвращает тройку TURN-allocate. Ошибки captcha запускают настроенную цепочку
// auto/manual solver.
// dom определяет набор доменов (vk.ru или vk.com).
func (c *Client) getTokenChain(ctx context.Context, link string, streamID int, creds VKCredentials, jar tlsclient.CookieJar, dom domainSet) (string, string, []string, error) {
	browser := c.pickBrowser()
	profile := browserprofile.ForKind(browser)

	httpClient, err := c.newTLSClientForBrowser(jar, browser)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to initialize tls_client: %w", err)
	}

	name := namegen.Generate()
	escapedName := neturl.QueryEscape(name)

	c.log.Infof("[STREAM %d] [VK Auth] Connecting Identity - Name: %s | User-Agent: %s | Domain: %s", streamID, name, profile.UserAgent, dom.WebDomain)

	// Шаг 1: анонимный app-токен (scopes — первичный режим).
	token1, err := c.fetchAnonToken(ctx, httpClient, profile, creds, anonTokenTypeScopes, dom)
	if err != nil {
		return "", "", nil, err
	}

	if delayErr := vkDelayRandom(ctx, 100, 150); delayErr != nil {
		return "", "", nil, delayErr
	}

	apiVersion := getAPIVersion(ctx, link, httpClient, profile, dom, func(format string, args ...any) {
		c.log.Infof("[STREAM %d] "+format, append([]any{streamID}, args...)...)
	})

	// Шаг 1a: прогрев getCallPreview (не критично).
	previewData := fmt.Sprintf("vk_join_link=https://"+dom.WebDomain+"/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	if _, prevErr := c.doRequest(ctx, httpClient, profile, previewData,
		"https://"+dom.APIDomain+"/method/calls.getCallPreview?v="+apiVersion+"&client_id="+creds.ClientID, dom); prevErr != nil {
		c.log.Warnf("[STREAM %d] [VK Auth] getCallPreview failed: %v", streamID, prevErr)
	}

	if delayErr := vkDelayRandom(ctx, 200, 400); delayErr != nil {
		return "", "", nil, delayErr
	}

	// Шаг 2: анонимный call-токен (здесь может сработать captcha).
	token2, err := c.fetchCallToken(ctx, httpClient, profile, streamID, link, escapedName, token1, creds, apiVersion, dom)
	if err != nil {
		// Fallback: если VK отклонил scopes-токен (anonym_token.not_found),
		// перезапрашиваем анонимный токен с token_type=messages.
		if strings.Contains(err.Error(), "anonym_token.not_found") {
			c.log.Warnf("[STREAM %d] [VK Auth] Scopes token rejected (anonym_token.not_found), retrying with token_type=messages", streamID)
			token1, retryErr := c.fetchAnonToken(ctx, httpClient, profile, creds, anonTokenTypeMessages, dom)
			if retryErr != nil {
				return "", "", nil, fmt.Errorf("token_type=messages fallback failed: %w (original: %v)", retryErr, err)
			}
			if delayErr := vkDelayRandom(ctx, 100, 150); delayErr != nil {
				return "", "", nil, delayErr
			}
			token2, err = c.fetchCallToken(ctx, httpClient, profile, streamID, link, escapedName, token1, creds, apiVersion, dom)
			if err != nil {
				return "", "", nil, fmt.Errorf("token_type=messages fallback also failed: %w", err)
			}
		} else {
			return "", "", nil, err
		}
	}

	if delayErr := vkDelayRandom(ctx, 100, 150); delayErr != nil {
		return "", "", nil, delayErr
	}

	// Шаг 3: ok.ru session_key.
	sessionKey, err := c.fetchOkRuSession(ctx, httpClient, profile, dom)
	if err != nil {
		return "", "", nil, err
	}

	if delayErr := vkDelayRandom(ctx, 100, 150); delayErr != nil {
		return "", "", nil, delayErr
	}

	// Шаг 4: TURN-реквизиты.
	user, pass, addresses, err := c.fetchTurnCreds(ctx, httpClient, profile, streamID, link, token2, sessionKey, dom)
	if err != nil {
		return "", "", nil, err
	}

	return user, pass, addresses, nil
}
