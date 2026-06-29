package vk

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/provider"
)

const (
	joinHostVK        = "vk.com"
	manualAuthTimeout = 5 * time.Minute
	manualCredTTL     = 10 * time.Minute
)

// manualProvider получает TURN-реквизиты через STDIN/STDOUT JSONL-протокол.
// При запросе credentials шлёт {"type":"auth_required","link":"..."} на STDOUT
// и ждёт {"type":"creds","link":"...","username":"...","credential":"...","urls":[...]}
// на STDIN. Потокобезопасен.
type manualProvider struct {
	link string
	log  logx.Logger

	mu          sync.Mutex
	cachedCreds map[string]*manualCreds // link -> cached
	pending     map[string]*authWaiter  // link -> waiter
}

type manualCreds struct {
	user    string
	pass    string
	addrs   []string
	expires time.Time
}

type authWaiter struct {
	done chan struct{}
	res  authWaitResult
}

type authWaitResult struct {
	creds *manualCreds
	err   error
}

// stdinCredsMsg - JSON из STDIN от хост-приложения.
type stdinCredsMsg struct {
	Type       string   `json:"type"`
	Link       string   `json:"link"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
	URLs       []string `json:"urls"`
	Cancel     bool     `json:"cancel"`
}

// stdoutAuthEvent - JSON на STDOUT для хост-приложения.
type stdoutAuthEvent struct {
	Type string `json:"type"`
	Link string `json:"link,omitempty"`
}

var (
	manualProviders   []*manualProvider
	manualProvidersMu sync.Mutex
	stdinReaderOnce   sync.Once
)

func newManualProvider(link string, log logx.Logger) *manualProvider {
	if log == nil {
		log = logx.Nop()
	}
	p := &manualProvider{
		link:        link,
		log:         log,
		cachedCreds: make(map[string]*manualCreds),
		pending:     make(map[string]*authWaiter),
	}
	manualProvidersMu.Lock()
	manualProviders = append(manualProviders, p)
	manualProvidersMu.Unlock()
	startStdinReader()
	return p
}

// startStdinReader запускает один глобальный reader STDIN при первом вызове.
func startStdinReader() {
	stdinReaderOnce.Do(func() {
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || line[0] != '{' {
					continue
				}
				var msg stdinCredsMsg
				if err := json.Unmarshal([]byte(line), &msg); err != nil {
					continue
				}
				if msg.Type != "creds" {
					continue
				}
				msg.Link = strings.TrimSpace(msg.Link)
				if msg.Link == "" {
					continue
				}
				manualProvidersMu.Lock()
				providers := append([]*manualProvider(nil), manualProviders...)
				manualProvidersMu.Unlock()
				for _, p := range providers {
					p.dispatchCreds(msg)
				}
			}
		}()
	})
}

func joinURL(hash string) string {
	return "https://" + joinHostVK + "/call/join/" + hash
}

func turnAddrs(urls []string) []string {
	var addrs []string
	for _, raw := range urls {
		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}
		clean := strings.Split(u, "?")[0]
		addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		addr = strings.TrimSpace(addr)
		if addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func (p *manualProvider) dispatchCreds(msg stdinCredsMsg) {
	p.mu.Lock()
	w, hasWait := p.pending[msg.Link]
	delete(p.pending, msg.Link)
	p.mu.Unlock()

	if msg.Cancel {
		if hasWait {
			w.res = authWaitResult{err: fmt.Errorf("auth cancelled by host app for link %s", msg.Link)}
			close(w.done)
		}
		p.log.Warnf("[MANUAL] auth cancelled for link %s", msg.Link)
		return
	}

	addrs := turnAddrs(msg.URLs)
	if msg.Username == "" || msg.Credential == "" || len(addrs) == 0 {
		p.log.Warnf("[MANUAL] incomplete creds for link %s", msg.Link)
		return
	}

	creds := &manualCreds{
		user:    msg.Username,
		pass:    msg.Credential,
		addrs:   addrs,
		expires: time.Now().Add(manualCredTTL),
	}

	p.mu.Lock()
	p.cachedCreds[msg.Link] = creds
	p.mu.Unlock()

	if hasWait {
		w.res = authWaitResult{creds: creds}
		close(w.done)
	}
	p.log.Infof("[MANUAL] received TURN creds for link %s (urls=%d)", msg.Link, len(addrs))
}

func (p *manualProvider) getCredentials(ctx context.Context) (provider.Credentials, error) {
	// Проверка кэша.
	p.mu.Lock()
	if c, ok := p.cachedCreds[p.link]; ok && time.Now().Before(c.expires) {
		creds := *c
		p.mu.Unlock()
		return provider.Credentials{User: creds.user, Pass: creds.pass, ServerAddrs: creds.addrs, ExpiresAt: creds.expires}, nil
	}
	p.mu.Unlock()

	// Создаём или присоединяемся к ожидающему waiter.
	p.mu.Lock()
	if existing, ok := p.pending[p.link]; ok {
		w := existing
		p.mu.Unlock()
		p.log.Infof("[MANUAL] auth already in flight for link %s, waiting...", p.link)
		return p.wait(ctx, w)
	}
	w := &authWaiter{done: make(chan struct{})}
	p.pending[p.link] = w
	p.mu.Unlock()

	// Шлём событие на STDOUT.
	u := joinURL(p.link)
	_ = json.NewEncoder(os.Stdout).Encode(stdoutAuthEvent{Type: "auth_required", Link: u})
	p.log.Infof("[MANUAL] auth required: %s (waiting on stdin)", u)

	return p.wait(ctx, w)
}

func (p *manualProvider) wait(ctx context.Context, w *authWaiter) (provider.Credentials, error) {
	waitCtx, cancel := context.WithTimeout(ctx, manualAuthTimeout)
	defer cancel()

	select {
	case <-w.done:
		if w.res.err != nil {
			return provider.Credentials{}, w.res.err
		}
		return provider.Credentials{
			User:        w.res.creds.user,
			Pass:        w.res.creds.pass,
			ServerAddrs: w.res.creds.addrs,
			ExpiresAt:   w.res.creds.expires,
		}, nil
	case <-waitCtx.Done():
		p.mu.Lock()
		delete(p.pending, p.link)
		p.mu.Unlock()
		reason := "auth timeout"
		if ctx.Err() != nil {
			reason = "auth aborted"
		}
		return provider.Credentials{}, fmt.Errorf("vk manual: %s", reason)
	}
}

func (*manualProvider) isAuthError(err error) bool {
	return err != nil
}

func (p *manualProvider) handleAuthError() bool {
	p.mu.Lock()
	delete(p.cachedCreds, p.link)
	p.mu.Unlock()
	p.log.Warnf("[MANUAL] auth error, invalidated creds for link %s", p.link)
	return true
}
