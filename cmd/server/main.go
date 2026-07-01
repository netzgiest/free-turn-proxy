package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
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

// WireGuard configuration defaults (override via env)
const (
	wgConfPathEnv = "WG_CONFIG_PATH"
	wgIfaceEnv    = "WG_INTERFACE"
	wgEndpointEnv = "WG_ENDPOINT"

	defaultWgConf     = "/etc/wireguard/wg0.conf"
	defaultWgIface    = "wg0"
	defaultWgEndpoint = "127.0.0.1:9000"
	wgSubnet          = "10.13.13"
)

type wgServerConf struct {
	PrivateKey string
	PublicKey  string
	ListenPort string
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func wgExec(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wg", args...)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("wg %s: %w", strings.Join(args, " "), err)
	}
	_ = out
	return nil
}

// wgGenKey generates a WireGuard keypair via wg genkey | wg pubkey
func wgGenKey() (priv, pub string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	privOut, err := exec.CommandContext(ctx, "wg", "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("wg genkey: %w", err)
	}
	priv = strings.TrimSpace(string(privOut))

	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	pubCmd := exec.CommandContext(ctx2, "wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(priv)
	pubOut, err := pubCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg pubkey: %w", err)
	}
	pub = strings.TrimSpace(string(pubOut))
	return priv, pub, nil
}

// deriveWGPubKey derives the public key from a WireGuard private key
func deriveWGPubKey(privKey string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wg", "pubkey")
	cmd.Stdin = strings.NewReader(privKey)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg pubkey: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// readWGServerConf parses wg0.conf and extracts server private key + listen port
func readWGServerConf(path string) (*wgServerConf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	conf := &wgServerConf{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inInterface := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[Interface]" {
			inInterface = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inInterface = false
			continue
		}
		if !inInterface {
			continue
		}
		if strings.HasPrefix(line, "PrivateKey") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				conf.PrivateKey = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "ListenPort") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				conf.ListenPort = strings.TrimSpace(parts[1])
			}
		}
	}

	if conf.PrivateKey != "" {
		pub, derr := deriveWGPubKey(conf.PrivateKey)
		if derr == nil {
			conf.PublicKey = pub
		}
	}

	return conf, nil
}

// wgGetNextAddress scans wg0.conf for the highest used IP in the subnet and returns the next one.
// If the file doesn't exist, returns the default first address.
func wgGetNextAddress(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return wgSubnet + ".2"
	}

	maxIP := 1
	prefix := wgSubnet + "."
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "AllowedIPs") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				ipStr := strings.TrimSpace(parts[1])
				ipStr = strings.Split(ipStr, "/")[0]
				if strings.HasPrefix(ipStr, prefix) {
					lastStr := ipStr[len(prefix):]
					last, cErr := strconv.Atoi(lastStr)
					if cErr == nil && last > maxIP {
						maxIP = last
					}
				}
			}
		}
	}

	return wgSubnet + "." + strconv.Itoa(maxIP+1)
}

// wgAddPeerToConf appends a [Peer] section to wg0.conf
func wgAddPeerToConf(path, pubKey, address, clientID string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	peerBlock := fmt.Sprintf("\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n",
		clientID, pubKey, address)
	_, err = f.WriteString(peerBlock)
	return err
}

// wgRemovePeerFromConf removes a [Peer] block matching the given public key from wg0.conf
func wgRemovePeerFromConf(path, pubKey string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var out []string
	i := 0
	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "[Peer]" {
			match := false
			for j := i + 1; j < len(lines); j++ {
				peerLine := strings.TrimSpace(lines[j])
				if peerLine == "" || strings.HasPrefix(peerLine, "[") {
					break
				}
				if strings.HasPrefix(peerLine, "PublicKey") {
					parts := strings.SplitN(peerLine, "=", 2)
					if len(parts) == 2 && strings.TrimSpace(parts[1]) == pubKey {
						match = true
					}
				}
			}
			if match {
				i++
				for i < len(lines) {
					peerLine := strings.TrimSpace(lines[i])
					if peerLine == "" || strings.HasPrefix(peerLine, "[") {
						break
					}
					i++
				}
				continue
			}
		}
		out = append(out, lines[i])
		i++
	}

	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600) //nolint:gosec // path from wgConfPath env/flag
}

// generateClientWGConfig builds a WireGuard client config string
func generateClientWGConfig(clientPrivKey, serverPubKey, address, endpoint string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = 1.1.1.1

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s
PersistentKeepalive = 25
`, clientPrivKey, address, serverPubKey, endpoint)
}

// buildShareURI creates a freeturn:// URI config from server config + client params
func buildShareURI(cfg *config.Server, clientID, comment, wgConf string) *uri.Config {
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

	host, port, _ := net.SplitHostPort(cfg.Proxy.Listen)
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = detectPublicIP()
	}
	peer := net.JoinHostPort(host, port)

	return &uri.Config{
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
		Comment:        comment,
		WgConf:         wgConf,
	}
}

// loadServerConfigFromPath attempts to parse a file path as a server config.
// If the path is empty or the file doesn't have server config fields, returns defaults.
func loadServerConfigFromPath(path string) *config.Server {
	if path == "" {
		return &config.Server{
			Proxy: config.ProxyOpts{
				Mode:   config.ProxyModeUDP,
				Listen: "0.0.0.0:56000",
			},
		}
	}

	data, err := os.ReadFile(path) //nolint:gosec // path from config flag
	if err != nil {
		return &config.Server{
			Proxy: config.ProxyOpts{
				Mode:   config.ProxyModeUDP,
				Listen: "0.0.0.0:56000",
			},
		}
	}

	var check struct {
		Connect string `json:"connect"`
	}
	if json.Unmarshal(data, &check) == nil && check.Connect != "" { //nolint:gosec
		cfg, pErr := config.ParseServerConfigFile(path)
		if pErr == nil {
			return cfg
		}
	}

	return &config.Server{
		Proxy: config.ProxyOpts{
			Mode:   config.ProxyModeUDP,
			Listen: "0.0.0.0:56000",
		},
	}
}

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

	wgConf := readWGConfig()

	u := buildShareURI(cfg, clientID, "", wgConf)

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

	// Оборачиваем conn в фильтр, пропускающий DTLS-keepalive (0xFF байты).
	if cfg.Proxy.Mode == config.ProxyModeTCPFwd {
		tcpfwdserver.Handle(ctx, logger, registry, dtlsConn, cfg.Proxy.Connect, cfg.KCP.Profile, cfg.KCP.FEC)
	} else {
		kaFilter := newKeepaliveFilter(dtlsConn, logger)
		udpserver.Handle(ctx, logger, kaFilter, cfg.Proxy.Connect)
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

// keepaliveFilter оборачивает net.Conn и фильтрует DTLS-keepalive (одиночный 0xFF байт)
// при чтении, не передавая их в data-path. Аналог server-side обработки из amurcanov/proxy-turn-vk-android.
type keepaliveFilter struct {
	net.Conn
	log logx.Logger
}

func newKeepaliveFilter(inner net.Conn, log logx.Logger) *keepaliveFilter {
	return &keepaliveFilter{Conn: inner, log: log}
}

func (f *keepaliveFilter) Read(b []byte) (int, error) {
	for {
		n, err := f.Conn.Read(b)
		if err != nil {
			return n, err
		}
		// Пропускаем одиночный 0xFF — DTLS keepalive от клиента.
		if n == 1 && b[0] == 0xFF {
			f.log.Debugf("keepalive: filtered 0xFF from client")
			continue
		}
		return n, nil
	}
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
		fmt.Println("Usage: server clients <add|remove|del|list|show> [args...]")
		os.Exit(1)
	}

	dbPath := configPath
	if dbPath == "" {
		dbPath = "clients.json"
		if envPath := os.Getenv("CLIENTS_FILE"); envPath != "" {
			dbPath = envPath
		}
	} else {
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
			comment = strings.Join(args[2:], " ")
		}

		wgPubKey := ""
		wgAddress := ""
		wgClientConf := ""
		wgErr := ""

		wgConfPath := getEnvOrDefault(wgConfPathEnv, defaultWgConf)
		wgIface := getEnvOrDefault(wgIfaceEnv, defaultWgIface)

		if _, lookErr := exec.LookPath("wg"); lookErr != nil {
			wgErr = "wg binary not found in PATH"
		} else if _, statErr := os.Stat(wgConfPath); statErr != nil {
			wgErr = fmt.Sprintf("wg conf not found: %v", statErr)
		} else {
			srvConf, rErr := readWGServerConf(wgConfPath)
			switch {
			case rErr != nil:
				wgErr = fmt.Sprintf("read wg conf: %v", rErr)
			case srvConf.PrivateKey == "":
				wgErr = "no PrivateKey in wg conf"
			default:
				cliPriv, cliPub, gErr := wgGenKey()
				if gErr != nil {
					wgErr = fmt.Sprintf("gen key: %v", gErr)
				} else {
					addr := wgGetNextAddress(wgConfPath)
					wgPubKey = cliPub
					wgAddress = addr

					if cErr := wgAddPeerToConf(wgConfPath, cliPub, addr, clientID); cErr != nil {
						wgErr = fmt.Sprintf("add peer to conf: %v", cErr)
					} else {
						_ = wgExec("set", wgIface, "peer", cliPub, "allowed-ips", addr+"/32")

						srvPubKey := srvConf.PublicKey
						wgEndpoint := getEnvOrDefault(wgEndpointEnv, defaultWgEndpoint)
						wgClientConf = generateClientWGConfig(cliPriv, srvPubKey, addr, wgEndpoint)
					}
				}
			}
		}

		if wgPubKey != "" {
			if dErr := db.AddWithWG(clientID, comment, wgPubKey, wgAddress, wgClientConf); dErr != nil {
				fmt.Printf("Failed to add client: %v\n", dErr)
				os.Exit(1)
			}
		} else {
			if dErr := db.Add(clientID, comment); dErr != nil {
				fmt.Printf("Failed to add client: %v\n", dErr)
				os.Exit(1)
			}
		}

		fmt.Printf("Client %s added successfully to %s\n", clientID, dbPath)
		if wgPubKey != "" {
			fmt.Printf("WireGuard peer created: pubkey=%s address=%s/32\n", wgPubKey, wgAddress)
		} else {
			fmt.Printf("WireGuard peer not created: %s\n", wgErr)
		}

		// Build and print freeturn:// URI + QR
		svrCfg := loadServerConfigFromPath(configPath)
		u := buildShareURI(svrCfg, clientID, comment, wgClientConf)
		fmt.Printf("\nShare link for client %s:\n%s\n", clientID, u.String())
		printQR("Share link for "+clientID, u.String())

	case "remove", "del":
		if len(args) < 2 {
			fmt.Println("Usage: server clients remove <client_id>")
			os.Exit(1)
		}
		clientID := args[1]

		// Look up client info before removing
		clients := db.List()
		info, exists := clients[clientID]
		wgPubKey := ""
		if exists {
			wgPubKey = info.WireGuardPubKey
		}

		if wgPubKey != "" {
			wgConfPath := getEnvOrDefault(wgConfPathEnv, defaultWgConf)
			wgIface := getEnvOrDefault(wgIfaceEnv, defaultWgIface)

			if _, lookErr := exec.LookPath("wg"); lookErr == nil {
				_ = wgExec("set", wgIface, "peer", wgPubKey, "remove")
			}

			if rErr := wgRemovePeerFromConf(wgConfPath, wgPubKey); rErr == nil {
				fmt.Printf("WireGuard peer %s removed\n", wgPubKey)
			}
		}

		if err := db.Remove(clientID); err != nil {
			fmt.Printf("Failed to remove client: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Client %s removed successfully from %s\n", clientID, dbPath)

	case "list":
		clients := db.List()
		if len(clients) == 0 {
			fmt.Printf("No clients in %s\n", dbPath)
			return
		}
		fmt.Printf("Found %d clients in %s:\n", len(clients), dbPath)
		for id, info := range clients {
			wgInfo := ""
			if info.WireGuardPubKey != "" {
				wgInfo = fmt.Sprintf(" wg_pub=%s addr=%s", info.WireGuardPubKey, info.WireGuardAddress)
			}
			fmt.Printf(" - %s (Comment: %s)%s\n", id, info.Comment, wgInfo)
		}

	case "show":
		if len(args) < 2 {
			fmt.Println("Usage: server clients show <client_id>")
			os.Exit(1)
		}
		clientID := args[1]
		clients := db.List()
		info, exists := clients[clientID]
		if !exists {
			fmt.Printf("Client %s not found in %s\n", clientID, dbPath)
			os.Exit(1)
		}

		svrCfg := loadServerConfigFromPath(configPath)
		wgCfg := info.WireGuardConfig

		u := buildShareURI(svrCfg, clientID, info.Comment, wgCfg)
		fmt.Printf("\nShare link for client %s:\n%s\n", clientID, u.String())
		printQR("Share link for "+clientID, u.String())

	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		fmt.Println("Usage: server clients <add|remove|del|list|show> [args...]")
		os.Exit(1)
	}
}
