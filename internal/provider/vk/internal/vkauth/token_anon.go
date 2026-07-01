package vkauth

import (
	"context"
	"fmt"

	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"

	tlsclient "github.com/bogdanfinn/tls-client"
)

// tokenType для fetchAnonToken.
const (
	anonTokenTypeScopes   = "scopes"
	anonTokenTypeMessages = "messages"
)

// fetchAnonToken - шаг 1 цепочки: обменивает app client_id/client_secret
// на анонимный access token через login.{vk.ru,vk.com}.
// Параметр tokenType управляет форматом запроса: anonTokenTypeScopes (по умолчанию,
// scopes=...) или anonTokenTypeMessages (token_type=messages — fallback для VK,
// когда scopes-токен даёт anonym_token.not_found в calls.getAnonymousToken).
// domain определяет login.vk.ru или login.vk.com.
func (c *Client) fetchAnonToken(ctx context.Context, httpClient tlsclient.HttpClient, profile browserprofile.Profile, creds VKCredentials, tokenType string, dom domainSet) (string, error) {
	var data string
	switch tokenType {
	case anonTokenTypeMessages:
		data = fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s",
			creds.ClientID, creds.ClientSecret, creds.ClientID)
	default:
		data = fmt.Sprintf("client_secret=%s&client_id=%s&scopes=audio_anonymous,video_anonymous,photos_anonymous,profile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=%s",
			creds.ClientSecret, creds.ClientID, creds.ClientID)
	}
	if c.log.DebugEnabled() {
		c.log.Debugf("[VK Auth] Fetching anon token type=%s client_id=%s domain=%s", tokenType, creds.ClientID, dom.LoginDomain)
	}
	resp, err := c.doRequest(ctx, httpClient, profile, data, "https://"+dom.LoginDomain+"/?act=get_anonym_token", dom)
	if err != nil {
		return "", err
	}
	dataMap, ok := resp["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("unexpected anon token response: %v", resp)
	}
	token, ok := dataMap["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("missing access_token in response: %v", resp)
	}
	if c.log.DebugEnabled() {
		c.log.Debugf("[VK Auth] Anon token received (len=%d)", len(token))
	}
	return token, nil
}
