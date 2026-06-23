package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/samosvalishe/free-turn-proxy/internal/clientsdb"
	"github.com/samosvalishe/free-turn-proxy/internal/config"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/proxy/bondserver"
	"github.com/samosvalishe/free-turn-proxy/internal/proxy/tcpfwdserver"
	"github.com/samosvalishe/free-turn-proxy/internal/proxy/udpserver"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/dtlsdial"
	"github.com/samosvalishe/free-turn-proxy/internal/uri"
	"github.com/samosvalishe/free-turn-proxy/internal/wire"
	"github.com/samosvalishe/free-turn-proxy/internal/wire/rtpopus"
	qrcode "github.com/skip2/go-qrcode"
)

// version is populated at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Ищем "clients" среди аргументов — он может быть не на первой позиции (из-за -config).
	if clientsIdx := findClientsArg(os.Args); clientsIdx >= 0 {
		before := os.Args[1:clientsIdx] // флаги до "clients" (напр. -config path)
		after := os.Args[clientsIdx+1:] // подкоманда после "clients"
		configPath := config.PeekConfigFlag(before)
		configPath2 := config.PeekConfigFlag(after)
		if configPath2 != "" {
			configPath = configPath2
		}
		args := stripConfigFlag(after)
		handleClientsCommand(args, configPath)
		return
	}

	cfg, err := config.ParseServer(os.Args[1:], os.Stderr)
	if err != nil {
		// -help/-h: usage уже напечатан в ParseServer, выходим штатно.
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		// логгер ещё не создан - единственный fatal до его инициализации.
		log.Fatalf("%v", err)
	}
	logger := logx.New(cfg.Log.Debug)
	logger.Infof("Free Turn Proxy server version=%s", version)

	if cfg.Obf.GenKey {
		key, gerr := rtpopus.GenKeyHex()
		if gerr != nil {
			logger.Errorf("gen-obf-key: %v", gerr)
			os.Exit(1)
		}
		fmt.Println(key)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		logger.Infof("Terminating...")
		cancel()
		select {
		case <-signalChan:
		case <-time.After(5 * time.Second):
		}
		logger.Warnf("Forced exit after shutdown timeout")
		cancel()
		os.Exit(1)
	}()

	addr, err := net.ResolveUDPAddr("udp", cfg.Proxy.Listen)
	if err != nil {
		logger.Errorf("resolve listen addr: %v", err)
		os.Exit(1)
	}
	logger.Infof("Starting server listen=%s connect=%s mode=%s obf-profile=%s bond-autodetect=true",
		cfg.Proxy.Listen, cfg.Proxy.Connect, cfg.Proxy.Mode, cfg.Obf.Profile)
	if !cfg.Obf.Enabled() {
		logger.Warnf("running with -obf-profile=none: any client reaching %s can relay to %s (no shared-key auth)", cfg.Proxy.Listen, cfg.Proxy.Connect)
	}

	certificate, genErr := dtlsdial.GenerateSelfSignedCert()
	if genErr != nil {
		logger.Errorf("self-signed cert: %v", genErr)
		os.Exit(1)
	}

	dtlsOpts := []dtls.ServerOption{
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
	}
	var listener net.Listener
	if cfg.Obf.Enabled() {
		logger.Infof("OBF profile=%s: listener only accepts clients with matching -obf-profile and -obf-key", cfg.Obf.Profile)
		obfListener, oerr := wire.Listen(string(cfg.Obf.Profile), addr, cfg.Obf.Key, cfg.Obf.Timing)
		if oerr != nil {
			logger.Errorf("obf listen: %v", oerr)
			os.Exit(1)
		}
		wire.SetLogfListener(obfListener, func(format string, args ...any) {
			logger.Debugf("[rtpopus3] "+format, args...)
		})
		listener, err = dtls.NewListenerWithOptions(obfListener, dtlsOpts...)
	} else {
		listener, err = dtls.ListenWithOptions("udp", addr, dtlsOpts...)
	}
	if err != nil {
		logger.Errorf("dtls listen: %v", err)
		os.Exit(1)
	}
	context.AfterFunc(ctx, func() {
		if err := listener.Close(); err != nil {
			logger.Errorf("listener close: %v", err)
		}
	})

	logger.Infof("Listening on %s", cfg.Proxy.Listen)

	registry := bondserver.NewRegistry(bondserver.Deps{Log: logger})

	var db *clientsdb.DB
	if cfg.ClientsFile != "" {
		d, err := clientsdb.New(cfg.ClientsFile)
		if err != nil {
			logger.Errorf("Failed to open clients-file: %v", err)
			os.Exit(1)
		}
		d.StartHotReload(10 * time.Second)
		db = d
		logger.Infof("Client ID authorization enabled via %s", cfg.ClientsFile)
	}

	printShareLink(cfg, logger)

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return
			}
			logger.Warnf("accept: %v", err)
			continue
		}
		wg.Go(func() {
			handleAccepted(ctx, logger, registry, db, conn, cfg)
		})
	}
}

func printShareLink(cfg *config.Server, logger logx.Logger) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		logger.Errorf("generate share client-id: %v", err)
		return
	}
	clientID := hex.EncodeToString(idBytes)

	mode := "udp"
	if cfg.Proxy.Mode == config.ProxyModeTCPFwd || cfg.Proxy.Mode == config.ProxyModeTCPFwdBond {
		mode = "tcp"
	}

	obfProfile := ""
	obfKey := ""
	if cfg.Obf.Enabled() {
		obfProfile = string(cfg.Obf.Profile)
		obfKey = hex.EncodeToString(cfg.Obf.Key)
	}

	host, port, err := net.SplitHostPort(cfg.Proxy.Listen)
	if err != nil {
		logger.Errorf("parse listen addr: %v", err)
		return
	}
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = detectPublicIP()
		if host == "" {
			logger.Errorf("detect public IP: no suitable address found")
			return
		}
	}
	peer := net.JoinHostPort(host, port)

	wgConf := readWGConfig()

	u := &uri.Config{
		Version:        1,
		Provider:       "vk",
		Peer:           peer,
		Transport:      "tcp",
		Mode:           mode,
		ObfProfile:     obfProfile,
		ObfKey:         obfKey,
		N:              10,
		StreamsPerCred: 10,
		ClientID:       clientID,
		Listen:         "127.0.0.1:9000",
		DNSMode:        "auto",
		WgConf:         wgConf,
	}

	logger.Infof("Share link: %s", u.String())
	logger.Infof("Add client to allowlist: %s clients add %s", os.Args[0], clientID)

	printQR("Share link", u.String())
}

func readWGConfig() string {
	const wgPath = "/opt/free-turn-proxy/wireguard-client.conf"
	data, err := os.ReadFile(wgPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func printQR(label, content string) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		fmt.Fprintf(os.Stderr, "QR error (%s): %v\n", label, err)
		return
	}
	fmt.Printf("\n=== %s QR ===\n%s\n", label, q.ToSmallString(false))
}

func detectPublicIP() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://ifconfig.me", nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		body, readErr := io.ReadAll(resp.Body)
		if readErr == nil {
			if ip := net.ParseIP(strings.TrimSpace(string(body))); ip != nil && ip.To4() != nil {
				return ip.String()
			}
		}
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsUnspecified() {
			continue
		}
		if ip := ipnet.IP.To4(); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func handleAccepted(ctx context.Context, logger logx.Logger, registry *bondserver.Registry, db *clientsdb.DB, conn net.Conn, cfg *config.Server) {
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			logger.Warnf("failed to close incoming connection: %s", closeErr)
		}
	}()
	logger.Debugf("Connection from %s", conn.RemoteAddr())

	ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel1()

	dtlsConn, ok := conn.(*dtls.Conn)
	if !ok {
		logger.Errorf("Type error: expected *dtls.Conn")
		return
	}
	logger.Debugf("Start handshake")
	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		logger.Warnf("Handshake failed: %v", err)
		return
	}
	logger.Debugf("Handshake done")

	// Client ID читается всегда (клиент всегда шлёт его первой app-record) -
	// wire-контракт симметричен. -clients-file включает только enforce по allowlist.
	clientID, err := clientsdb.ReadClientID(dtlsConn)
	if err != nil {
		logger.Warnf("Read Client ID failed: %v", err)
		return
	}
	if db != nil {
		if !db.IsAuthorized(clientID) {
			logger.Warnf("Unauthorized Client ID: %s. Dropping connection.", clientID)
			return
		}
		logger.Debugf("Client %s authorized", clientID)
	} else {
		logger.Debugf("Client ID received (no allowlist): %s", clientID)
	}

	if cfg.Proxy.Mode == config.ProxyModeTCPFwd {
		tcpfwdserver.Handle(ctx, logger, registry, dtlsConn, cfg.Proxy.Connect, cfg.KCP.Profile, cfg.KCP.FEC)
	} else {
		udpserver.Handle(ctx, logger, conn, cfg.Proxy.Connect)
	}

	logger.Debugf("Connection closed: %s", conn.RemoteAddr())
}

// findClientsArg ищет позицию "clients" в os.Args (пропуская имя программы).
// Возвращает -1 если не найден.
func findClientsArg(args []string) int {
	for i := 1; i < len(args); i++ {
		if args[i] == "clients" {
			return i
		}
	}
	return -1
}

// stripConfigFlag удаляет -config <path> из args (независимо от формы: -config=X или -config X).
func stripConfigFlag(args []string) []string {
	out := make([]string, 0, len(args))
	skip := false
	for i, a := range args {
		if skip {
			skip = false
			continue
		}
		if a == "-config" || a == "--config" {
			// Следующий аргумент — значение, если оно не в форме -config=X
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				skip = true
			}
			continue
		}
		if strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--config=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

func handleClientsCommand(args []string, configPath string) {
	if len(args) == 0 {
		fmt.Println("Usage: server clients <add|remove|list> [args...]")
		os.Exit(1)
	}

	// Если указан -config, клиенты хранятся внутри конфига
	dbPath := configPath
	if dbPath == "" {
		dbPath = "clients.json"
		if envPath := os.Getenv("CLIENTS_FILE"); envPath != "" {
			dbPath = envPath
		}
	} else {
		// Если config-файла нет, создаём шаблон
		if _, statErr := os.Stat(dbPath); statErr != nil { //nolint:gosec
			if errors.Is(statErr, os.ErrNotExist) {
				dbPath = filepath.Clean(dbPath)
				if writeErr := os.WriteFile(dbPath, []byte(config.DefaultConfigTemplate()), 0o600); writeErr != nil {
					fmt.Printf("Failed to create %s: %v\n", dbPath, writeErr)
					os.Exit(1)
				}
				fmt.Printf("Created %s\n", dbPath)
			} else {
				fmt.Printf("Failed to stat %s: %v\n", dbPath, statErr)
				os.Exit(1)
			}
		}
	}

	db, err := clientsdb.New(dbPath)
	if err != nil {
		fmt.Printf("Failed to open %s: %v\n", dbPath, err)
		os.Exit(1)
	}

	cmd := args[0]
	switch cmd {
	case "add":
		if len(args) < 2 {
			fmt.Println("Usage: server clients add <client_id> [comment]")
			os.Exit(1)
		}
		clientID := args[1]
		comment := ""
		if len(args) > 2 {
			comment = args[2]
		}
		if err := db.Add(clientID, comment); err != nil {
			fmt.Printf("Failed to add client: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Client %s added successfully to %s\n", clientID, dbPath)
	case "remove":
		if len(args) < 2 {
			fmt.Println("Usage: server clients remove <client_id>")
			os.Exit(1)
		}
		clientID := args[1]
		if err := db.Remove(clientID); err != nil {
			fmt.Printf("Failed to remove client: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Client %s removed successfully from %s\n", clientID, dbPath)
	case "list":
		clients := db.List()
		fmt.Printf("Found %d clients in %s:\n", len(clients), dbPath)
		for id, info := range clients {
			fmt.Printf(" - %s (Comment: %s)\n", id, info.Comment)
		}
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}
