package vkauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/captcha"

	tlsclient "github.com/bogdanfinn/tls-client"
)

// DefaultAutoSolve запускает in-page widget flow. Загружает сохранённый профиль
// браузера, если доступен, - капча видит стабильные fingerprints на этапе
// загрузки страницы и POST-запроса.
func DefaultAutoSolve(
	ctx context.Context,
	captchaErr *captcha.Error,
	streamID int,
	client tlsclient.HttpClient,
	profile browserprofile.Profile,
) (string, error) {
	log := captcha.Log
	log.Infof("[STREAM %d] [Captcha] Solving captcha...", streamID)

	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri for auto-solve")
	}
	if captchaErr.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri for auto-solve")
	}

	var savedProfile *browserprofile.Saved
	if sp, err := browserprofile.Load(); err == nil {
		if sameBrowserFamily(profile, sp.Profile) {
			log.Infof("[STREAM %d] [Captcha] Using saved real browser profile", streamID)
			savedProfile = sp
		} else {
			log.Debugf("[STREAM %d] [Captcha] Saved browser profile (UA=%q) differs from current (UA=%q), skipping",
				streamID, sp.UserAgent, profile.UserAgent)
		}
	}

	successToken, err := captcha.Solve(ctx, captchaErr, streamID, client, profile, savedProfile, log)
	if err != nil {
		return "", err
	}
	log.Infof("[STREAM %d] [Captcha] solver succeeded", streamID)
	return successToken, nil
}

// sameBrowserFamily проверяет, что два профиля принадлежат одному семейству
// (одинаковая ОС и браузерный движок). Несовместимые сохранённые профили
// (например, Android Chrome Mobile при текущем Windows Firefox) пропускаются,
// чтобы VK не видел противоречие UA ↔ device fingerprints.
func sameBrowserFamily(a, b browserprofile.Profile) bool {
	aWin := strings.Contains(a.UserAgent, "Windows NT")
	bWin := strings.Contains(b.UserAgent, "Windows NT")
	if aWin != bWin {
		return false
	}
	aFirefox := strings.Contains(a.UserAgent, "Firefox") || strings.Contains(a.UserAgent, "Gecko/")
	bFirefox := strings.Contains(b.UserAgent, "Firefox") || strings.Contains(b.UserAgent, "Gecko/")
	return aFirefox == bFirefox
}
