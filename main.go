package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAddr      = ":20002"
	defaultConfig    = "./config.json"
	commandTimeout   = 8 * time.Second
	maxPayloadBytes  = 1 << 20
	sessionCookieKey = "ufwui_session"
	sessionTTL       = 12 * time.Hour
)

type applyRuleRequest struct {
	Ports    string `json:"ports"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
}

type ufwToggleRequest struct {
	Action string `json:"action"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type configFile struct {
	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password"`
}

type authConfig struct {
	AdminUser     string
	AdminPassword string
}

type apiResponse struct {
	OK      bool        `json:"ok"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ruleItem struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Policy    string `json:"policy"`
	Direction string `json:"direction"`
}

type applyResult struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Action    string `json:"action"`
	ExitOK    bool   `json:"exit_ok"`
	Output    string `json:"output"`
	ErrorText string `json:"error_text,omitempty"`
}

type sessionStore struct {
	mu     sync.RWMutex
	tokens map[string]time.Time
}

var (
	ruleLinePattern = regexp.MustCompile(`^(\d+)/(tcp|udp)\s+(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT))?.*$`)
	authCfg         authConfig
	sessions        = &sessionStore{tokens: map[string]time.Time{}}
)

func main() {
	if err := execSanityCheck(); err != nil {
		log.Fatalf("startup check failed: %v", err)
	}

	cfg, err := loadConfig(envOrDefault("CONFIG_FILE", defaultConfig))
	if err != nil {
		log.Fatalf("config check failed: %v", err)
	}
	authCfg = cfg

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/login", loginHandler)
	mux.HandleFunc("/api/logout", logoutHandler)
	mux.HandleFunc("/api/me", meHandler)
	mux.Handle("/api/status", requireAuth(http.HandlerFunc(statusHandler)))
	mux.Handle("/api/ufw", requireAuth(http.HandlerFunc(ufwToggleHandler)))
	mux.Handle("/api/rules", requireAuth(http.HandlerFunc(applyRuleHandler)))
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	addr := envOrDefault("PORT", defaultAddr)
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           withLogging(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
	}

	log.Printf("ufw-ui server started on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func execSanityCheck() error {
	if _, err := exec.LookPath("ufw"); err != nil {
		return errors.New("`ufw` command not found; install ufw before running this service")
	}
	if runtime.GOOS == "linux" {
		if os.Geteuid() != 0 {
			log.Println("warning: service is not running as root; ufw commands may fail without sudo privileges")
		}
	}
	return nil
}

func loadConfig(path string) (authConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return authConfig{}, fmt.Errorf("read config file failed: %w", err)
	}
	var cfg configFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return authConfig{}, fmt.Errorf("parse config file failed: %w", err)
	}
	cfg.AdminUser = strings.TrimSpace(cfg.AdminUser)
	cfg.AdminPassword = strings.TrimSpace(cfg.AdminPassword)
	if cfg.AdminUser == "" || cfg.AdminPassword == "" {
		return authConfig{}, errors.New("config requires non-empty admin_user and admin_password")
	}
	return authConfig{AdminUser: cfg.AdminUser, AdminPassword: cfg.AdminPassword}, nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Message: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Message: "ok"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Message: "method not allowed"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{OK: false, Message: "invalid json payload"})
		return
	}
	if req.Username != authCfg.AdminUser || req.Password != authCfg.AdminPassword {
		writeJSON(w, http.StatusUnauthorized, apiResponse{OK: false, Message: "invalid username or password"})
		return
	}

	token, err := generateToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{OK: false, Message: "generate session failed"})
		return
	}
	sessions.set(token, time.Now().Add(sessionTTL))

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieKey,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   false,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	writeJSON(w, http.StatusOK, apiResponse{OK: true, Message: "login success", Data: map[string]string{"username": authCfg.AdminUser}})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Message: "method not allowed"})
		return
	}

	if c, err := r.Cookie(sessionCookieKey); err == nil && strings.TrimSpace(c.Value) != "" {
		sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieKey,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   false,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Message: "logout success"})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Message: "method not allowed"})
		return
	}
	if isAuthorized(r) {
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Data: map[string]string{"username": authCfg.AdminUser}})
		return
	}
	writeJSON(w, http.StatusUnauthorized, apiResponse{OK: false, Message: "unauthorized"})
}

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAuthorized(r) {
			writeJSON(w, http.StatusUnauthorized, apiResponse{OK: false, Message: "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isAuthorized(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieKey)
	if err != nil {
		return false
	}
	token := strings.TrimSpace(c.Value)
	if token == "" {
		return false
	}
	return sessions.valid(token)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Message: "method not allowed"})
		return
	}

	stdout, stderr, err := runUFW("status")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{OK: false, Message: fmt.Sprintf("read status failed: %v; %s", err, stderr)})
		return
	}

	rules := parseRules(stdout)
	ufwStatus, ufwActive := parseUFWStatus(stdout)
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Data: map[string]interface{}{
		"raw":        stdout,
		"rules":      rules,
		"ufw_status": ufwStatus,
		"ufw_active": ufwActive,
	}})
}

func ufwToggleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Message: "method not allowed"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes)
	var req ufwToggleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{OK: false, Message: "invalid json payload"})
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != "enable" && action != "disable" {
		writeJSON(w, http.StatusBadRequest, apiResponse{OK: false, Message: "action must be one of: enable, disable"})
		return
	}

	stdout, stderr, err := runUFW(action)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResponse{OK: false, Message: fmt.Sprintf("ufw %s failed: %v", action, err), Data: map[string]string{
			"output": strings.TrimSpace(strings.Join([]string{stdout, stderr}, "\n")),
		}})
		return
	}

	statusOut, statusErr, statusRunErr := runUFW("status")
	if statusRunErr != nil {
		writeJSON(w, http.StatusBadGateway, apiResponse{OK: false, Message: fmt.Sprintf("read status failed after %s: %v; %s", action, statusRunErr, statusErr)})
		return
	}
	ufwStatus, ufwActive := parseUFWStatus(statusOut)

	writeJSON(w, http.StatusOK, apiResponse{OK: true, Message: fmt.Sprintf("ufw %s success", action), Data: map[string]interface{}{
		"output":     strings.TrimSpace(strings.Join([]string{stdout, stderr}, "\n")),
		"ufw_status": ufwStatus,
		"ufw_active": ufwActive,
	}})
}

func applyRuleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Message: "method not allowed"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes)
	var req applyRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{OK: false, Message: "invalid json payload"})
		return
	}

	ports, err := parsePortList(req.Ports)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{OK: false, Message: err.Error()})
		return
	}

	action := normalizeAction(req.Action)
	if action == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{OK: false, Message: "action must be one of: open, close"})
		return
	}

	protocols := normalizeProtocols(req.Protocol)
	if len(protocols) == 0 {
		writeJSON(w, http.StatusBadRequest, apiResponse{OK: false, Message: "protocol must be one of: tcp, udp, both"})
		return
	}

	results := make([]applyResult, 0, len(ports)*len(protocols))
	var failed int
	for _, port := range ports {
		for _, protocol := range protocols {
			args := ufwArgs(action, port, protocol)
			stdout, stderr, runErr := runUFW(args...)
			result := applyResult{
				Port:     port,
				Protocol: protocol,
				Action:   action,
				ExitOK:   runErr == nil,
				Output:   strings.TrimSpace(strings.Join([]string{stdout, stderr}, "\n")),
			}
			if runErr != nil {
				failed++
				result.ErrorText = runErr.Error()
			}
			results = append(results, result)
		}
	}

	statusCode := http.StatusOK
	msg := "operation completed"
	if failed > 0 {
		statusCode = http.StatusBadGateway
		msg = fmt.Sprintf("operation completed with %d failure(s)", failed)
	}

	writeJSON(w, statusCode, apiResponse{OK: failed == 0, Message: msg, Data: map[string]interface{}{
		"results": results,
		"failed":  failed,
	}})
}

func parsePortList(input string) ([]int, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, errors.New("ports is required, example: 22,80,443")
	}

	replacer := strings.NewReplacer("\n", ",", "\t", ",", " ", ",", ";", ",")
	normalized := replacer.Replace(trimmed)
	parts := strings.Split(normalized, ",")
	seen := map[int]struct{}{}
	ports := make([]int, 0, len(parts))

	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("port out of range: %d", n)
		}
		if _, exists := seen[n]; !exists {
			seen[n] = struct{}{}
			ports = append(ports, n)
		}
	}

	if len(ports) == 0 {
		return nil, errors.New("no valid ports found")
	}
	sort.Ints(ports)
	return ports, nil
}

func normalizeAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "open", "allow":
		return "open"
	case "close", "deny", "delete":
		return "close"
	default:
		return ""
	}
}

func normalizeProtocols(input string) []string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "tcp":
		return []string{"tcp"}
	case "udp":
		return []string{"udp"}
	case "both", "all", "tcpudp", "udp/tcp":
		return []string{"tcp", "udp"}
	default:
		return nil
	}
}

func ufwArgs(action string, port int, protocol string) []string {
	portProto := fmt.Sprintf("%d/%s", port, protocol)
	if action == "open" {
		return []string{"allow", portProto}
	}
	return []string{"delete", "allow", portProto}
}

func runUFW(args ...string) (stdout string, stderr string, runErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	start := time.Now()
	cmdLine := "ufw " + strings.Join(args, " ")
	log.Printf("[CMD] exec: %s", cmdLine)

	cmd := exec.CommandContext(ctx, "ufw", args...)
	cmd.Stdin = strings.NewReader("y\n")
	outBytes, err := cmd.Output()
	if err == nil {
		stdout = strings.TrimSpace(string(outBytes))
		log.Printf("[CMD] done: %s (ok, %s)", cmdLine, time.Since(start))
		return stdout, "", nil
	}

	var ee *exec.ExitError
	if errors.As(err, &ee) {
		stdout = strings.TrimSpace(string(outBytes))
		stderr = strings.TrimSpace(string(ee.Stderr))
		log.Printf("[CMD] done: %s (failed, %s) err=%v stderr=%q", cmdLine, time.Since(start), err, stderr)
		return stdout, stderr, err
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		runErr = errors.New("command timeout")
		log.Printf("[CMD] done: %s (timeout, %s)", cmdLine, time.Since(start))
		return "", "", runErr
	}
	log.Printf("[CMD] done: %s (error, %s) err=%v", cmdLine, time.Since(start), err)
	return "", "", err
}

func parseRules(status string) []ruleItem {
	lines := strings.Split(status, "\n")
	rules := make([]ruleItem, 0)
	for _, line := range lines {
		clean := strings.TrimSpace(line)
		if clean == "" || strings.HasPrefix(clean, "Status:") || strings.HasPrefix(clean, "To") || strings.HasPrefix(clean, "--") {
			continue
		}
		match := ruleLinePattern.FindStringSubmatch(clean)
		if len(match) == 0 {
			continue
		}
		port, _ := strconv.Atoi(match[1])
		direction := "IN"
		if match[4] != "" {
			direction = match[4]
		}
		rules = append(rules, ruleItem{
			Port:      port,
			Protocol:  strings.ToLower(match[2]),
			Policy:    strings.ToUpper(match[3]),
			Direction: direction,
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Port == rules[j].Port {
			return rules[i].Protocol < rules[j].Protocol
		}
		return rules[i].Port < rules[j].Port
	})
	return rules
}

func parseUFWStatus(status string) (string, bool) {
	lines := strings.Split(status, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "status:") {
			raw := strings.TrimSpace(trimmed[len("Status:"):])
			state := strings.ToLower(raw)
			return state, state == "active"
		}
	}
	return "unknown", false
}

func generateToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *sessionStore) set(token string, expireAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = expireAt
}

func (s *sessionStore) valid(token string) bool {
	now := time.Now()
	s.mu.RLock()
	expireAt, ok := s.tokens[token]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if now.After(expireAt) {
		s.delete(token)
		return false
	}
	return true
}

func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

func writeJSON(w http.ResponseWriter, status int, payload apiResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).String())
	})
}

func envOrDefault(key, fallback string) string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	return val
}
