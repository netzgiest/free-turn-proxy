package vkauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"
	"github.com/samosvalishe/free-turn-proxy/internal/randx"

	tlsclient "github.com/bogdanfinn/tls-client"
)

// Config конфигурирует Client. Нулевые значения - безопасные дефолты,
// кроме Dialer (должен быть задан явно для кастомного DNS).
type Config struct {
	// Credentials для перебора по порядку. nil/empty -> DefaultCredentials.
	Credentials []VKCredentials

	// Dialer для HTTP-транспорта запросов к VK API.
	Dialer net.Dialer

	// ManualOnly форсирует ручной путь captcha с первой попытки.
	ManualOnly bool

	// StreamsPerCache - делитель streamID -> cacheID. <=0 -> дефолт.
	StreamsPerCache int

	// StreamsAlive возвращает число подключённых потоков; используется для
	// решения, является ли исчерпанная captcha фатальной или только throttle.
	// nil -> 1.
	StreamsAlive func() int32

	// AutoSolver / ManualSolver - подключаемые решалки captcha. nil отключает
	// соответствующий путь (поток переходит к следующей попытке).
	AutoSolver   AutoSolveFunc
	ManualSolver ManualSolveFunc

	// Browser - браузерный профиль (UA + JA3 + client hints) для control-plane.
	// Нулевое значение -> Firefox (KindFromString("") -> Firefox).
	Browser browserprofile.Kind

	// RandBrowser включает случайный выбор браузера для каждой сессии.
	// При RandBrowser=true Browser игнорируется.
	RandBrowser bool

	// Log - уровневый логгер. nil -> no-op.
	Log logx.Logger
}

// Client - фасад VK-аутентификации и кэша реквизитов. Владеет кэшем группы
// потоков, глобальным throttle запросов, таймером блокировки captcha и счётчиком
// ошибок аутентификации для инвалидации устаревших TURN-реквизитов.
type Client struct {
	credentials []VKCredentials
	dialer      net.Dialer
	manualOnly  bool
	browser     browserprofile.Kind
	randBrowser bool
	streamsFn   func() int32
	autoSolver  AutoSolveFunc
	manualSolve ManualSolveFunc
	log         logx.Logger

	store *Store

	lockout atomic.Int64

	fetchMu       sync.Mutex
	lastFetchTime time.Time

	// tokenChain - 4-шаговый получатель токена для пары credentials.
	// В prod подключён (*Client).getTokenChain; тесты подменяют fake.
	tokenChain tokenChainFn

	// minFetchIntervalFn ограничивает частоту запросов к VK. Тесты снижают.
	minFetchIntervalFn func() time.Duration

	backgroundCtx    context.Context
	backgroundCancel context.CancelFunc
	pendingRefreshes sync.Map // cacheID -> chan struct{} (закрывается при завершении)
}

type tokenChainFn func(ctx context.Context, link string, streamID int, creds VKCredentials, jar tlsclient.CookieJar, dom domainSet) (string, string, []string, error)

func New(cfg Config) *Client {
	c := &Client{
		credentials: cfg.Credentials,
		dialer:      cfg.Dialer,
		manualOnly:  cfg.ManualOnly,
		browser:     cfg.Browser,
		randBrowser: cfg.RandBrowser,
		streamsFn:   cfg.StreamsAlive,
		autoSolver:  cfg.AutoSolver,
		manualSolve: cfg.ManualSolver,
		log:         cfg.Log,
		store:       NewStore(cfg.StreamsPerCache),
	}
	if len(c.credentials) == 0 {
		c.credentials = DefaultCredentials
	}
	if c.log == nil {
		c.log = logx.Nop()
	}
	if c.streamsFn == nil {
		c.streamsFn = func() int32 { return 1 }
	}
	c.tokenChain = c.getTokenChain
	c.minFetchIntervalFn = func() time.Duration {
		return 3*time.Second + time.Duration(randx.Intn(3000))*time.Millisecond
	}
	c.backgroundCtx, c.backgroundCancel = context.WithCancel(context.Background())
	return c
}

// Close отменяет фоновые goroutine обновления credentials.
// После Close Client непригоден к использованию.
func (c *Client) Close() {
	if c.backgroundCancel != nil {
		c.backgroundCancel()
	}
}

// GetCredentials возвращает TURN-реквизиты для streamID, включая ExpiresAt —
// время истечения credentials (нужно для make-before-break в TURN-аллокации).
// Адреса отдаются в порядке предпочтения для streamID (предпочтительный первым).
func (c *Client) GetCredentials(ctx context.Context, link string, streamID int) (user, pass string, addrs []string, expiresAt time.Time, err error) {
	cache := c.store.Get(streamID)
	cacheID := c.store.CacheID(streamID)

	cache.mutex.RLock()
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) && len(cache.creds.ServerAddrs) > 0 {
		expires := time.Until(cache.creds.ExpiresAt)
		u, p := cache.creds.Username, cache.creds.Password
		addrs = orderAddrs(cache.creds.ServerAddrs, streamID)
		expAt := cache.creds.ExpiresAt
		cache.mutex.RUnlock()
		c.log.Debugf("[STREAM %d] [VK Auth] Using cached credentials (cache=%d, expires in %v, server=%s)", streamID, cacheID, expires, addrs[0])
		if expires < RefreshLeadTime {
			c.scheduleRefresh(ctx, cacheID, link)
		}
		return u, p, addrs, expAt, nil
	}
	cache.mutex.RUnlock()

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) && len(cache.creds.ServerAddrs) > 0 {
		expires := time.Until(cache.creds.ExpiresAt)
		if expires < RefreshLeadTime {
			c.scheduleRefresh(ctx, cacheID, link)
		}
		return cache.creds.Username, cache.creds.Password, orderAddrs(cache.creds.ServerAddrs, streamID), cache.creds.ExpiresAt, nil
	}

	user, pass, addrs, err = c.fetchSerialized(ctx, link, streamID)
	if err != nil {
		return "", "", nil, time.Time{}, err
	}

	expiresAt = time.Now().Add(CredentialLifetime - CacheSafetyMargin)
	cache.creds = TurnCredentials{
		Username:    user,
		Password:    pass,
		ServerAddrs: addrs,
		ExpiresAt:   expiresAt,
		Link:        link,
	}
	c.scheduleRefresh(ctx, cacheID, link)
	return user, pass, orderAddrs(addrs, streamID), expiresAt, nil
}

// orderAddrs возвращает копию addrs, ротированную так, что предпочтительный
// для streamID адрес стоит первым, остальные - следом (сохраняя порядок).
// Раскидывает primary по стримам (балансировка relay-IP), оставляя остальные
// как фоллбэк при DPI-дропе.
func orderAddrs(addrs []string, streamID int) []string {
	n := len(addrs)
	if n <= 1 {
		return append([]string(nil), addrs...)
	}
	k := streamID % n
	out := make([]string, 0, n)
	out = append(out, addrs[k:]...)
	out = append(out, addrs[:k]...)
	return out
}

// HandleAuthError увеличивает счётчик ошибок аутентификации кэша потока и
// инвалидирует кэш при достижении порога внутри скользящего окна.
// Возвращает true при инвалидации.
func (c *Client) HandleAuthError(streamID int) bool {
	cache := c.store.Get(streamID)
	cacheID := c.store.CacheID(streamID)
	now := time.Now().Unix()

	if now-cache.lastErrorTime.Load() > int64(ErrorWindow.Seconds()) {
		cache.errorCount.Store(0)
	}
	count := cache.errorCount.Add(1)
	cache.lastErrorTime.Store(now)

	c.log.Warnf("[STREAM %d] [VK Auth] Auth error (cache=%d, count=%d/%d)", streamID, cacheID, count, MaxCacheErrors)

	if count >= MaxCacheErrors {
		c.log.Warnf("[VK Auth] Multiple auth errors (%d), invalidating cache %d for stream %d", count, cacheID, streamID)
		cache.Invalidate()
		c.log.Warnf("[STREAM %d] [VK Auth] Credentials cache invalidated", streamID)
		return true
	}
	return false
}

// ResetErrors обнуляет счётчик ошибок аутентификации (вызывать при успешном allocate).
func (c *Client) ResetErrors(streamID int) {
	c.store.Get(streamID).errorCount.Store(0)
}

// scheduleRefresh запускает фоновую goroutine обновления кэша cacheID
// перед expiry, чтобы при re-allocate не ждать VK API. Использует
// backgroundCtx (отменяется при Close). Гарантирует не более одного
// ожидающего обновления на cacheID через pendingRefreshes.
func (c *Client) scheduleRefresh(ctx context.Context, cacheID int, link string) {
	if c.backgroundCtx == nil {
		return
	}
	// Проверяем, нет ли уже активного обновления для этого cacheID.
	if _, loaded := c.pendingRefreshes.LoadOrStore(cacheID, make(chan struct{})); loaded {
		return
	}

	go func() {
		_ = ctx // caller context, используем backgroundCtx
		cache := c.store.Get(c.streamIDForCache(cacheID))
		raw, _ := c.pendingRefreshes.Load(cacheID)
		done, ok := raw.(chan struct{})
		if !ok {
			return
		}
		defer close(done)
		defer c.pendingRefreshes.Delete(cacheID)

		// Ждём до RefreshLeadTime до expiry.
		cache.mutex.RLock()
		expiresAt := cache.creds.ExpiresAt
		cache.mutex.RUnlock()

		wait := time.Until(expiresAt) - RefreshLeadTime
		if wait <= 0 {
			wait = 0
		}
		select {
		case <-c.backgroundCtx.Done():
			return
		case <-time.After(wait):
		}

		// Могла произойти инвалидация или другой refresh — проверяем.
		cache.mutex.RLock()
		stale := cache.creds.Link != link || time.Now().After(cache.creds.ExpiresAt)
		cache.mutex.RUnlock()
		if stale {
			return
		}

		streamID := c.store.CacheID(cacheID)*c.store.StreamsPerCache() + 1
		c.log.Debugf("[VK Auth] Background refresh for cache %d (link=%s)", cacheID, link)

		ctx, cancel := context.WithTimeout(c.backgroundCtx, 30*time.Second)
		defer cancel()

		//nolint:contextcheck // background goroutine uses its own derived context
		user, pass, addrs, err := c.fetchSerialized(ctx, link, streamID)
		if err != nil {
			c.log.Warnf("[VK Auth] Background refresh failed for cache %d: %v (next fetch will retry)", cacheID, err)
			return
		}
		cache.mutex.Lock()
		cache.creds = TurnCredentials{
			Username:    user,
			Password:    pass,
			ServerAddrs: addrs,
			ExpiresAt:   time.Now().Add(CredentialLifetime - CacheSafetyMargin),
			Link:        link,
		}
		cache.mutex.Unlock()
		c.log.Infof("[VK Auth] Background refresh succeeded for cache %d (new expiry in %v)", cacheID, CredentialLifetime-CacheSafetyMargin)

		// Запланировать следующий refresh для нового expiry.
		c.scheduleRefresh(c.backgroundCtx, cacheID, link) //nolint:contextcheck
	}()
}

// streamIDForCache возвращает streamID, соответствующий cacheID.
// Используется для логирования и throttle (fetchSerialized).
func (c *Client) streamIDForCache(cacheID int) int {
	return cacheID*c.store.StreamsPerCache() + 1
}

// LockoutUntilUnix возвращает unix-секунду дедлайна глобальной блокировки captcha
// или 0, если блокировки нет.
func (c *Client) LockoutUntilUnix() int64 {
	return c.lockout.Load()
}

// BackoffUntilUnix реализует provider.Provider - алиас LockoutUntilUnix.
// vkauth-lockout глобальный (без per-stream), streamID-параметра в самом
// методе нет; интерфейс provider.Provider определяет no-arg сигнатуру.
func (c *Client) BackoffUntilUnix() int64 { return c.LockoutUntilUnix() }

// Name реализует provider.Provider.
func (*Client) Name() string { return "vk" }

// pickBrowser возвращает браузер для текущей сессии. При randBrowser=true
// каждая сессия получает случайный браузер. Иначе — фиксированный cfg.Browser.
func (c *Client) pickBrowser() browserprofile.Kind {
	if c.randBrowser {
		return browserprofile.RandomKind()
	}
	return c.browser
}

// IsAuthError оборачивает пакетный IsAuthError как метод для работы через интерфейс.
func (*Client) IsAuthError(err error) bool { return IsAuthError(err) }

// engageLockout устанавливает глобальную блокировку captcha на d с момента вызова.
func (c *Client) engageLockout(d time.Duration) {
	c.lockout.Store(time.Now().Add(d).Unix())
}

// fetchSerialized соблюдает интервал 3s+jitter между запросами, затем
// выполняет перебор всех credentials.
func (c *Client) fetchSerialized(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()

	minInterval := c.minFetchIntervalFn()
	elapsed := time.Since(c.lastFetchTime)
	if !c.lastFetchTime.IsZero() && elapsed < minInterval {
		wait := minInterval - elapsed
		c.log.Debugf("[STREAM %d] [VK Auth] Throttling: waiting %v to prevent rate limit", streamID, wait.Truncate(time.Millisecond))
		select {
		case <-ctx.Done():
			return "", "", nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	defer func() { c.lastFetchTime = time.Now() }()
	return c.fetch(ctx, link, streamID)
}

// domainOrder определяет порядок перебора доменов для каждого credentials.
// Сначала пробуем vk.ru (исторически стабильный), при сетевой ошибке — vk.com.
var domainOrder = []domainSet{DomainVkRu, DomainVkCom}

// fetch перебирает c.credentials, возвращая первый успех или терминальную ошибку.
// Для каждого credentials сначала пробует DomainVkRu, затем DomainVkCom.
func (c *Client) fetch(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	if time.Now().Unix() < c.lockout.Load() {
		return "", "", nil, fmt.Errorf("%w: %w", ErrCaptchaWaitRequired, ErrLockoutActive)
	}

	var lastErr error
	jar := tlsclient.NewCookieJar()
	if c.log.DebugEnabled() {
		c.log.Debugf("[STREAM %d] [VK Auth] Starting credential chain for link=%s, %d credentials, %d domains", streamID, link, len(c.credentials), len(domainOrder))
	}
	for _, creds := range c.credentials {
		for _, dom := range domainOrder {
			c.log.Infof("[STREAM %d] [VK Auth] Trying credentials: client_id=%s domain=%s", streamID, creds.ClientID, dom.WebDomain)

			chainStart := time.Now()
			user, pass, addrs, err := c.tokenChain(ctx, link, streamID, creds, jar, dom)
			if c.log.DebugEnabled() {
				c.log.Debugf("[STREAM %d] [VK Auth] Token chain took %dms", streamID, time.Since(chainStart).Milliseconds())
			}
			if err == nil {
				c.log.Infof("[STREAM %d] [VK Auth] Success with client_id=%s domain=%s", streamID, creds.ClientID, dom.WebDomain)
				return user, pass, addrs, nil
			}
			lastErr = err
			c.log.Warnf("[STREAM %d] [VK Auth] Failed with client_id=%s domain=%s: %v", streamID, creds.ClientID, dom.WebDomain, err)

			if errors.Is(err, ErrCaptchaWaitRequired) || errors.Is(err, ErrFatalCaptchaNoStreams) {
				return "", "", nil, err
			}
			es := err.Error()
			if strings.Contains(es, "error_code:29") || strings.Contains(es, "error_code: 29") || strings.Contains(es, "Rate limit") {
				c.log.Warnf("[STREAM %d] [VK Auth] Rate limit detected, trying next credentials/domain", streamID)
			}
		}
	}
	return "", "", nil, fmt.Errorf("all VK credentials failed: %w", lastErr)
}

func vkDelayRandom(ctx context.Context, minMs, maxMs int) error {
	ms := minMs + randx.Intn(maxMs-minMs+1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(ms) * time.Millisecond):
		return nil
	}
}
