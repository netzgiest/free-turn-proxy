package vkauth

import (
	"errors"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/provider"
)

// VKCredentials - пара app_id/app_secret для получения анонимных токенов.
type VKCredentials struct {
	ClientID     string
	ClientSecret string
}

// TurnCredentials - разрешённые TURN-реквизиты для группы потоков.
type TurnCredentials struct {
	Username    string
	Password    string
	ServerAddrs []string
	ExpiresAt   time.Time
	Link        string
}

// DefaultCredentials - публичные app_id/secret официальных VK-клиентов. Это НЕ
// приватные креды пользователя - VK раздаёт их в JS-бандле страницы калла.
// Клиент перебирает по порядку при ошибках авторизации. В списке только app_id
// с доступом к calls.getAnonymousToken (проверено живым звонком); приложения
// без calls-scope ("Unknown method passed") исключены.
//
//nolint:gosec // public VK SDK app credentials, not user secrets
var DefaultCredentials = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"},  // VK_WEB_APP_ID (secret 1)
	{ClientID: "6287487", ClientSecret: "MuAxFaKDYDOICzGnEOhp"},  // VK_WEB_APP_ID (secret 2, from proxy-turn-vk-android)
	{ClientID: "8202606", ClientSecret: "lMRsTiMCyPnp5vfoldmn"},  // VK_WEB_APP_ID 2 (from proxy-turn-vk-android)
	{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw"},  // VK_MVK_APP_ID
	{ClientID: "2274003", ClientSecret: "hHbZxrka2uZ6jB1inYsH"},  // VK_ANDROID_APP
	{ClientID: "51453752", ClientSecret: "4UyuCUsdK8pVCNoeQuGi"}, // VK_MESSENGER_DESKTOP
	{ClientID: "3140623", ClientSecret: "VeWdmVclDCtn6ihuP1nt"},  // VK_IPHONE_APP
}

// APIVersion - версия VK API во всех calls.* запросах. Держать единой и близкой
// к версии живого web-клиента звонка (рассинхрон = fingerprint-аномалия).
const APIVersion = "5.282"

const (
	CredentialLifetime = 10 * time.Minute
	CacheSafetyMargin  = 60 * time.Second

	// RefreshLeadTime - за сколько до expiry начинать фоновое обновление
	// credentials, чтобы при re-allocate не ждать VK API.
	RefreshLeadTime = 90 * time.Second

	MaxCacheErrors = 3
	ErrorWindow    = 10 * time.Second

	DefaultStreamsPerCache = 10
)

// Sentinel-ошибки auth-потока. Строковые формы стабильны (используются в логах).
//
// ErrCaptchaWaitRequired и ErrFatalCaptchaNoStreams также матчатся через
// provider.ErrBackoffActive / provider.ErrFatalNoStreams - pipeline проверяет
// generic-sentinels, vkauth-внутренний код может проверять и старые.
var (
	ErrCaptchaWaitRequired   = errors.Join(provider.ErrBackoffActive, errors.New("CAPTCHA_WAIT_REQUIRED"))
	ErrFatalCaptchaNoStreams = errors.Join(provider.ErrFatalNoStreams, errors.New("FATAL_CAPTCHA_FAILED_NO_STREAMS"))
	ErrLockoutActive         = errors.New("global lockout active")
)

// domainSet содержит домены для одного варианта VK API (vk.ru или vk.com).
// Перебор начинается с DomainVkRu; если все credentials упали с сетевой
// ошибкой, переходим на DomainVkCom.
type domainSet struct {
	LoginDomain string
	APIDomain   string
	WebDomain   string
}

var (
	DomainVkRu = domainSet{
		LoginDomain: "login.vk.ru",
		APIDomain:   "api.vk.ru",
		WebDomain:   "vk.ru",
	}
	DomainVkCom = domainSet{
		LoginDomain: "login.vk.com",
		APIDomain:   "api.vk.com",
		WebDomain:   "vk.com",
	}
)
