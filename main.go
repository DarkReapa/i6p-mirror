package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sys/unix"
)

const appName = "I6P Project Mirror"

type Repo struct {
	Name        string `json:"name"`
	Remote      string `json:"remote"`
	LocalSubdir string `json:"local_subdir"`
	Enabled     bool   `json:"enabled"`
}

type Config struct {
	Domain           string   `json:"domain"`
	Email            string   `json:"email"`
	DataDir          string   `json:"data_dir"`
	StateDir         string   `json:"state_dir"`
	BindHTTP         string   `json:"bind_http"`
	BindHTTPS        string   `json:"bind_https"`
	BindRsync        string   `json:"bind_rsync"`
	SyncEveryMinutes int      `json:"sync_every_minutes"`
	RsyncDelete      bool     `json:"rsync_delete"`
	RsyncBwlimitKBps int      `json:"rsync_bwlimit_kbps"`
	RsyncExtraArgs   []string `json:"rsync_extra_args"`
	Repos            []Repo   `json:"repos"`
}

func listenTCPv6Only(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			if err := c.Control(func(fd uintptr) {
				ctrlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
			}); err != nil {
				return err
			}
			return ctrlErr
		},
	}

	return lc.Listen(context.Background(), "tcp6", addr)
}

func defaultConfig(dataDir string) Config {
	stateDir := "/var/lib/i6p-mirror"
	return Config{
		Domain:           "mirror.i6p.example",
		Email:            "admin@i6p.example",
		DataDir:          dataDir,
		StateDir:         stateDir,
		BindHTTP:         "[::]:80",
		BindHTTPS:        "[::]:443",
		BindRsync:        "[::]:873",
		SyncEveryMinutes: 120,
		RsyncDelete:      true,
		RsyncBwlimitKBps: 0,
		RsyncExtraArgs:   []string{},
		Repos: []Repo{
			{Name: "archlinux", Remote: "rsync://mirror.i6p.ovh::archlinux", LocalSubdir: "archlinux", Enabled: true},
			{Name: "almalinux", Remote: "rsync://mirror.i6p.ovh::almalinux", LocalSubdir: "almalinux", Enabled: true},
			{Name: "debian", Remote: "rsync://mirror.i6p.ovh::debian", LocalSubdir: "debian", Enabled: true},
			{Name: "debian-cd", Remote: "rsync://mirror.i6p.ovh::debian-cd", LocalSubdir: "debian-cd", Enabled: true},
			{Name: "debian-security", Remote: "rsync://mirror.i6p.ovh::debian-security", LocalSubdir: "debian-security", Enabled: true},
			{Name: "ubuntu", Remote: "rsync://mirror.i6p.ovh::ubuntu", LocalSubdir: "ubuntu", Enabled: true},
			{Name: "ubuntu-releases", Remote: "rsync://mirror.i6p.ovh::ubuntu-releases", LocalSubdir: "ubuntu-releases", Enabled: true},
		},
	}
}

func loadConfig(path string, fallback Config) (Config, error) {
	if path == "" {
		return fallback, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	applyDefaults(&cfg, fallback)
	return cfg, nil
}

func applyDefaults(cfg *Config, def Config) {
	if cfg.Domain == "" {
		cfg.Domain = def.Domain
	}
	if cfg.Email == "" {
		cfg.Email = def.Email
	}
	if cfg.DataDir == "" {
		cfg.DataDir = def.DataDir
	}
	if cfg.StateDir == "" {
		cfg.StateDir = def.StateDir
	}
	if cfg.BindHTTP == "" {
		cfg.BindHTTP = def.BindHTTP
	}
	if cfg.BindHTTPS == "" {
		cfg.BindHTTPS = def.BindHTTPS
	}
	if cfg.BindRsync == "" {
		cfg.BindRsync = def.BindRsync
	}
	if cfg.SyncEveryMinutes == 0 {
		cfg.SyncEveryMinutes = def.SyncEveryMinutes
	}
	if cfg.RsyncExtraArgs == nil {
		cfg.RsyncExtraArgs = def.RsyncExtraArgs
	}
	if cfg.Repos == nil || len(cfg.Repos) == 0 {
		cfg.Repos = def.Repos
	}
}

type syncManager struct {
	cfg     Config
	logger  *log.Logger
	mu      sync.Mutex
	running bool
	lastRun time.Time
	lastErr string
}

func (s *syncManager) status() (running bool, lastRun time.Time, lastErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running, s.lastRun, s.lastErr
}

func (s *syncManager) setStatus(running bool, lastRun time.Time, lastErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = running
	if !lastRun.IsZero() {
		s.lastRun = lastRun
	}
	s.lastErr = lastErr
}

func ensureDir(p string) error {
	return os.MkdirAll(p, 0o755)
}

func sanitizeModuleName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "/", "-")
	return name
}

func writeRsyncdConf(cfg Config) (string, error) {
	confDir := filepath.Join(cfg.StateDir, "rsyncd")
	if err := ensureDir(confDir); err != nil {
		return "", err
	}
	confPath := filepath.Join(confDir, "rsyncd.conf")
	pidFile := filepath.Join(confDir, "rsyncd.pid")

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "pid file = %s\n", pidFile)
	fmt.Fprintf(&buf, "use chroot = no\n")
	fmt.Fprintf(&buf, "read only = true\n")
	fmt.Fprintf(&buf, "max connections = 50\n")
	fmt.Fprintf(&buf, "timeout = 600\n")
	fmt.Fprintf(&buf, "refuse options = delete\n")
	fmt.Fprintf(&buf, "log file = %s\n", filepath.Join(confDir, "rsyncd.log"))
	fmt.Fprintf(&buf, "\n")

	for _, r := range cfg.Repos {
		if !r.Enabled {
			continue
		}
		mod := sanitizeModuleName(r.Name)
		path := filepath.Join(cfg.DataDir, r.LocalSubdir)
		if err := ensureDir(path); err != nil {
			return "", err
		}
		fmt.Fprintf(&buf, "[%s]\n", mod)
		fmt.Fprintf(&buf, "  path = %s\n", path)
		fmt.Fprintf(&buf, "  comment = %s - %s\n", appName, mod)
		fmt.Fprintf(&buf, "  list = true\n")
		fmt.Fprintf(&buf, "  uid = nobody\n")
		fmt.Fprintf(&buf, "  gid = nogroup\n")
		fmt.Fprintf(&buf, "\n")
	}

	if err := os.WriteFile(confPath, buf.Bytes(), 0o644); err != nil {
		return "", err
	}
	return confPath, nil
}

func startRsyncDaemon(ctx context.Context, cfg Config, logger *log.Logger) (*exec.Cmd, error) {
	confPath, err := writeRsyncdConf(cfg)
	if err != nil {
		return nil, err
	}

	args := []string{"--daemon", "--no-detach", "--config=" + confPath}

	host, port, err := net.SplitHostPort(cfg.BindRsync)
	if err != nil {
		port = strings.TrimPrefix(cfg.BindRsync, ":")
		host = ""
	}
	if port != "" {
		args = append(args, "--port="+port)
	}
	if host != "" {
		args = append(args, "--address="+host)
	}

	cmd := exec.CommandContext(ctx, "rsync", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	logger.Printf("Starting rsync daemon: rsync %s", strings.Join(args, " "))
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func isAddrAlreadyInUse(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.Is(opErr.Err, syscall.EADDRINUSE)
	}

	return false
}

func shouldStartEmbeddedRsyncd(bindAddr string) (bool, error) {
	ln, err := listenTCPv6Only(bindAddr)
	if err != nil {
		if isAddrAlreadyInUse(err) {
			return false, nil
		}
		return true, err
	}
	_ = ln.Close()
	return true, nil
}

func (s *syncManager) rsyncOne(ctx context.Context, repo Repo) error {
	if !repo.Enabled {
		return nil
	}

	local := filepath.Join(s.cfg.DataDir, repo.LocalSubdir)
	if err := ensureDir(local); err != nil {
		return err
	}

	args := []string{"-aH", "--partial", "--delay-updates", "--numeric-ids", "--safe-links", "--timeout=600"}
	if s.cfg.RsyncDelete {
		args = append(args, "--delete", "--delete-delay")
	}
	if s.cfg.RsyncBwlimitKBps > 0 {
		args = append(args, fmt.Sprintf("--bwlimit=%d", s.cfg.RsyncBwlimitKBps))
	}
	args = append(args, s.cfg.RsyncExtraArgs...)

	remote := repo.Remote
	if !strings.HasSuffix(remote, "/") {
		remote += "/"
	}
	dst := local + string(os.PathSeparator)

	args = append(args, remote, dst)

	s.logger.Printf("Sync %s: rsync %s", repo.Name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, "rsync", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (s *syncManager) runOnce(ctx context.Context) {
	s.setStatus(true, time.Time{}, "")
	defer s.setStatus(false, time.Now(), s.lastErr)

	start := time.Now()
	s.logger.Printf("Sync started (%d repos)", len(s.cfg.Repos))

	for _, r := range s.cfg.Repos {
		select {
		case <-ctx.Done():
			s.logger.Printf("Sync cancelled")
			s.setStatus(false, time.Now(), "cancelled")
			return
		default:
		}
		if !r.Enabled {
			continue
		}
		if err := s.rsyncOne(ctx, r); err != nil {
			msg := fmt.Sprintf("%s: %v", r.Name, err)
			s.logger.Printf("ERROR sync %s", msg)
			s.setStatus(true, time.Time{}, msg)
		}
	}

	s.logger.Printf("Sync finished in %s", time.Since(start).Truncate(time.Second))
}

func (s *syncManager) startScheduler(ctx context.Context) {
	go s.runOnce(ctx)

	t := time.NewTicker(time.Duration(s.cfg.SyncEveryMinutes) * time.Minute)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				running, _, _ := s.status()
				if running {
					s.logger.Printf("Skip scheduled sync: previous still running")
					continue
				}
				go s.runOnce(ctx)
			}
		}
	}()
}

var indexTpl = template.Must(template.New("index").Parse(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{{.Title}}</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;margin:24px;line-height:1.4}
    .card{max-width:920px}
    h1{margin:0 0 8px 0}
    .muted{color:#555}
    code{background:#f3f3f3;padding:2px 6px;border-radius:6px}
    ul{padding-left:18px}
    .box{background:#fafafa;border:1px solid #eee;border-radius:12px;padding:14px;margin-top:16px}
  </style>
</head>
<body>
  <div class="card">
    <h1>{{.Title}}</h1>
    <div class="muted">HTTP/HTTPS/rsync mirror service</div>

    <div class="box">
      <div><b>Status:</b></div>
      <div>Sync running: <code>{{.Running}}</code></div>
      <div>Last run: <code>{{.LastRun}}</code></div>
      <div>Last error: <code>{{.LastErr}}</code></div>
    </div>

    <h2>Repositories</h2>
    <ul>
      {{range .Repos}}
        {{if .Enabled}}
          <li>
            <b>{{.Name}}</b> —
            <a href="/{{.LocalSubdir}}/">{{.LocalSubdir}}</a>
            <span class="muted">(remote: {{.Remote}})</span>
          </li>
        {{end}}
      {{end}}
    </ul>

    <h2>rsync access</h2>
    <div class="box">
      Use: <code>rsync://{{.Domain}}/&lt;module&gt;</code><br/>
      Example: <code>rsync rsync://{{.Domain}}/debian/</code>
    </div>

  </div>
</body>
</html>
`))

func makeMux(cfg Config, sm *syncManager) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		running, lastRun, lastErr := sm.status()
		lastRunStr := "never"
		if !lastRun.IsZero() {
			lastRunStr = lastRun.Format(time.RFC3339)
		}
		data := map[string]any{
			"Title":   appName,
			"Domain":  cfg.Domain,
			"Running": running,
			"LastRun": lastRunStr,
			"LastErr": lastErr,
			"Repos":   cfg.Repos,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = indexTpl.Execute(w, data)
	})

	for _, repo := range cfg.Repos {
		if !repo.Enabled {
			continue
		}
		prefix := "/" + strings.Trim(repo.LocalSubdir, "/") + "/"
		local := filepath.Join(cfg.DataDir, repo.LocalSubdir)
		fs := http.StripPrefix(prefix, http.FileServer(http.Dir(local)))
		mux.Handle(prefix, fs)
	}

	adminToken := os.Getenv("I6P_ADMIN_TOKEN")
	mux.HandleFunc("/admin/sync", func(w http.ResponseWriter, r *http.Request) {
		if adminToken == "" {
			http.Error(w, "admin disabled (I6P_ADMIN_TOKEN not set)", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Query().Get("token") != adminToken {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		running, _, _ := sm.status()
		if running {
			http.Error(w, "sync already running", http.StatusConflict)
			return
		}
		go sm.runOnce(context.Background())
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "sync started\n")
	})

	return mux
}

func mustAbs(p string) string {
	ap, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return ap
}

func checkDeps() error {
	_, err := exec.LookPath("rsync")
	if err != nil {
		return errors.New("rsync not found in PATH. Install rsync package")
	}
	return nil
}

func main() {
	var (
		cfgPath = flag.String("config", "", "Path to JSON config")
		dataDir = flag.String("data-dir", "", "Mirror data directory (overrides config)")
		domain  = flag.String("domain", "", "Domain for HTTPS (overrides config)")
	)
	flag.Parse()

	if err := checkDeps(); err != nil {
		log.Fatal(err)
	}

	dd := os.Getenv("DATA_DIR")
	if dd == "" {
		dd = "/srv/mirror"
	}
	if *dataDir != "" {
		dd = *dataDir
	}

	def := defaultConfig(dd)
	cfg, err := loadConfig(*cfgPath, def)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if env := os.Getenv("DOMAIN"); env != "" {
		cfg.Domain = env
	}
	if env := os.Getenv("EMAIL"); env != "" {
		cfg.Email = env
	}
	if env := os.Getenv("STATE_DIR"); env != "" {
		cfg.StateDir = env
	}
	if env := os.Getenv("BIND_HTTP"); env != "" {
		cfg.BindHTTP = env
	}
	if env := os.Getenv("BIND_HTTPS"); env != "" {
		cfg.BindHTTPS = env
	}
	if env := os.Getenv("BIND_RSYNC"); env != "" {
		cfg.BindRsync = env
	}

	if *domain != "" {
		cfg.Domain = *domain
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}

	cfg.DataDir = mustAbs(cfg.DataDir)
	cfg.StateDir = mustAbs(cfg.StateDir)

	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Printf("%s starting", appName)
	logger.Printf("Domain: %s", cfg.Domain)
	logger.Printf("DataDir: %s", cfg.DataDir)
	logger.Printf("StateDir: %s", cfg.StateDir)
	logger.Printf("HTTP: %s | HTTPS: %s | RSYNC: %s", cfg.BindHTTP, cfg.BindHTTPS, cfg.BindRsync)

	if err := ensureDir(cfg.DataDir); err != nil {
		log.Fatal(err)
	}
	if err := ensureDir(cfg.StateDir); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sm := &syncManager{cfg: cfg, logger: logger}
	sm.startScheduler(ctx)

	startEmbeddedRsyncd, probeErr := shouldStartEmbeddedRsyncd(cfg.BindRsync)
	if !startEmbeddedRsyncd {
		logger.Printf("Skip embedded rsync daemon: %s is already in use", cfg.BindRsync)
	} else {
		if probeErr != nil {
			logger.Printf("WARNING: rsync bind preflight failed on %s: %v", cfg.BindRsync, probeErr)
		}

		rsyncCmd, err := startRsyncDaemon(ctx, cfg, logger)
		if err != nil {
			logger.Printf("WARNING: cannot start rsync daemon: %v", err)
			logger.Printf("If you need rsync:// access, ensure you run as root (or setcap) and rsync supports --address (optional).")
		} else {
			go func() {
				err := rsyncCmd.Wait()
				if err != nil {
					logger.Printf("rsync daemon exited: %v", err)
				} else {
					logger.Printf("rsync daemon exited")
				}
			}()
		}
	}

	certCacheDir := filepath.Join(cfg.StateDir, "cert-cache")
	if err := ensureDir(certCacheDir); err != nil {
		log.Fatal(err)
	}

	mgr := &autocert.Manager{
		Cache:      autocert.DirCache(certCacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Email:      cfg.Email,
	}

	mux := makeMux(cfg, sm)

	httpSrv := &http.Server{
		Addr: cfg.BindHTTP,
		Handler: mgr.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + cfg.Domain + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})),
	}

	tlsCfg := mgr.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12

	httpsSrv := &http.Server{
		Addr:      cfg.BindHTTPS,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	lnHTTP, err := listenTCPv6Only(cfg.BindHTTP)
	if err != nil {
		logger.Fatalf("HTTP listen v6only failed on %s: %v", cfg.BindHTTP, err)
	}
	lnHTTPS, err := listenTCPv6Only(cfg.BindHTTPS)
	if err != nil {
		logger.Fatalf("HTTPS listen v6only failed on %s: %v", cfg.BindHTTPS, err)
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Printf("HTTP(v6only) listening on %s", cfg.BindHTTP)
		if err := httpSrv.Serve(lnHTTP); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("HTTP server error: %v", err)
			cancel()
		}
	}()

	go func() {
		logger.Printf("HTTPS(v6only) listening on %s", cfg.BindHTTPS)
		if err := httpsSrv.ServeTLS(lnHTTPS, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("HTTPS server error: %v", err)
			cancel()
		}
	}()

	<-sigCh
	logger.Printf("Shutting down...")

	shCtx, shCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer shCancel()

	_ = httpSrv.Shutdown(shCtx)
	_ = httpsSrv.Shutdown(shCtx)
	_ = lnHTTP.Close()
	_ = lnHTTPS.Close()

	logger.Printf("Bye.")
}
