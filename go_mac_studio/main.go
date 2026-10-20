package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type UserAccount struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Role      string `json:"role"`
	Credits   int64  `json:"credits"`
	CreatedAt string `json:"created_at"`
}

type DeviceRecord struct {
	ID            int64   `json:"id"`
	Email         string  `json:"email"`
	Password      string  `json:"password"`
	Phone         string  `json:"phone"`
	TokenKey      string  `json:"token_key"`
	TOTPSecret    string  `json:"totp_secret"`
	LastCode      string  `json:"last_code"`
	LastCodeAt    float64 `json:"last_code_at"`
	ADSID         string  `json:"adsid"`
	UDID          string  `json:"udid"`
	SerialNumber  string  `json:"serial_number"`
	ServerModel   string  `json:"server_model"`
	Status        string  `json:"status"`
	CreatedAt     string  `json:"created_at"`
	AdiPbB64      string  `json:"adi_pb_b64"`
	HostUUID      string  `json:"host_uuid"`
	MID           string  `json:"mid"`
	RoutingData   string  `json:"routing_data"`
	LocalUserUUID string  `json:"local_user_uuid"`
	ClientInfo    string  `json:"client_info"`
	OwnerUser     string  `json:"owner_user"`
}

type DeviceStore struct {
	mu      sync.RWMutex
	dbPath  string
	pool    *AdiEnginePool
	byToken map[string]*DeviceRecord
	byEmail map[string]*DeviceRecord
	byID    map[int64]*DeviceRecord
	ordered []*DeviceRecord
	users   map[string]*UserAccount
}

func NewDeviceStore(dbPath string, pool *AdiEnginePool) (*DeviceStore, error) {
	s := &DeviceStore{
		dbPath:  dbPath,
		pool:    pool,
		byToken: make(map[string]*DeviceRecord),
		byEmail: make(map[string]*DeviceRecord),
		byID:    make(map[int64]*DeviceRecord),
		users:   make(map[string]*UserAccount),
	}
	if err := s.ReloadFromDB(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *DeviceStore) ReloadFromDB() error {
	rows, err := s.pool.DBLoadAll(s.dbPath)
	if err != nil {
		return err
	}
	uRows, _ := s.pool.DBUsersLoad(s.dbPath)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.byToken = make(map[string]*DeviceRecord)
	s.byEmail = make(map[string]*DeviceRecord)
	s.byID = make(map[int64]*DeviceRecord)
	s.ordered = nil
	s.users = make(map[string]*UserAccount)

	for _, u := range uRows {
		ua := &UserAccount{
			Username:  strings.ToLower(strings.TrimSpace(getStringField(u, "username"))),
			Password:  getStringField(u, "password"),
			Role:      strings.ToUpper(getStringField(u, "role")),
			Credits:   toInt64(u["credits"]),
			CreatedAt: getStringField(u, "created_at"),
		}
		if ua.Username != "" {
			s.users[ua.Username] = ua
		}
	}
	if _, ok := s.users["mina"]; !ok {
		s.users["mina"] = &UserAccount{
			Username:  "mina",
			Password:  "mina-vip",
			Role:      "ADMIN",
			Credits:   9999999,
			CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
		}
	}

	for _, r := range rows {
		owner := strings.ToLower(strings.TrimSpace(getStringField(r, "owner_user")))
		if owner == "" {
			owner = "mina"
		}
		rec := &DeviceRecord{
			ID:            toInt64(r["id"]),
			Email:         getStringField(r, "email"),
			Password:      getStringField(r, "password"),
			Phone:         getStringField(r, "phone"),
			TokenKey:      getStringField(r, "token_key"),
			TOTPSecret:    getStringField(r, "totp_secret"),
			LastCode:      getStringField(r, "last_code"),
			ADSID:         getStringField(r, "adsid"),
			UDID:          getStringField(r, "udid"),
			SerialNumber:  getStringField(r, "serial_number"),
			ServerModel:   getStringField(r, "server_model"),
			Status:        getStringField(r, "status"),
			CreatedAt:     getStringField(r, "created_at"),
			AdiPbB64:      getStringField(r, "adi_pb_b64"),
			HostUUID:      getStringField(r, "host_uuid"),
			MID:           getStringField(r, "mid"),
			RoutingData:   getStringField(r, "routing_data"),
			LocalUserUUID: getStringField(r, "local_user_uuid"),
			ClientInfo:    getStringField(r, "client_info"),
			OwnerUser:     owner,
		}
		if rec.TokenKey != "" {
			s.byToken[rec.TokenKey] = rec
		}
		if rec.Email != "" {
			s.byEmail[strings.ToLower(rec.Email)] = rec
		}
		if rec.ID > 0 {
			s.byID[rec.ID] = rec
		}
		s.ordered = append(s.ordered, rec)
	}
	return nil
}

func (s *DeviceStore) AuthenticateUser(username, password string) *UserAccount {
	u := strings.ToLower(strings.TrimSpace(username))
	p := strings.TrimSpace(password)
	s.mu.RLock()
	defer s.mu.RUnlock()
	acc, ok := s.users[u]
	if !ok || acc.Password != p {
		return nil
	}
	cp := *acc
	return &cp
}

func (s *DeviceStore) GetUser(username string) *UserAccount {
	u := strings.ToLower(strings.TrimSpace(username))
	s.mu.RLock()
	defer s.mu.RUnlock()
	acc, ok := s.users[u]
	if !ok {
		return nil
	}
	cp := *acc
	return &cp
}

func (s *DeviceStore) HasCredits(username string) bool {
	u := strings.ToLower(strings.TrimSpace(username))
	s.mu.RLock()
	defer s.mu.RUnlock()
	acc, ok := s.users[u]
	if !ok {
		return false
	}
	return acc.Role == "ADMIN" || acc.Credits > 0
}

func (s *DeviceStore) DeductCredit(username string) {
	u := strings.ToLower(strings.TrimSpace(username))
	s.mu.Lock()
	acc, ok := s.users[u]
	if !ok || acc.Role == "ADMIN" {
		s.mu.Unlock()
		return
	}
	if acc.Credits > 0 {
		acc.Credits--
	}
	uMap := map[string]interface{}{
		"username": acc.Username,
		"password": acc.Password,
		"role":     acc.Role,
		"credits":  acc.Credits,
	}
	s.mu.Unlock()
	_ = s.pool.DBUserUpsert(s.dbPath, uMap)
}

func (s *DeviceStore) UpsertUser(username, password, role string, credits int64) error {
	uname := strings.ToLower(strings.TrimSpace(username))
	if uname == "" || password == "" {
		return fmt.Errorf("username and password required")
	}
	role = strings.ToUpper(strings.TrimSpace(role))
	if role != "ADMIN" {
		role = "USER"
	}
	err := s.pool.DBUserUpsert(s.dbPath, map[string]interface{}{
		"username": uname,
		"password": password,
		"role":     role,
		"credits":  credits,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.users[uname] = &UserAccount{
		Username:  uname,
		Password:  password,
		Role:      role,
		Credits:   credits,
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	s.mu.Unlock()
	return nil
}

func (s *DeviceStore) DeleteUser(username string) error {
	uname := strings.ToLower(strings.TrimSpace(username))
	if uname == "mina" {
		return fmt.Errorf("cannot delete primary admin")
	}
	if err := s.pool.DBUserDelete(s.dbPath, uname); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.users, uname)
	s.mu.Unlock()
	return nil
}

func (s *DeviceStore) ListUsers() []UserAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []UserAccount
	for _, u := range s.users {
		list = append(list, *u)
	}
	return list
}

func makeAuthToken(username, password string) string {
	mac := hmac.New(sha256.New, []byte("almino_secret_key_2026:"+password))
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(username))))
	return strings.ToLower(strings.TrimSpace(username)) + ":" + hex.EncodeToString(mac.Sum(nil))[:32]
}

func (s *DeviceStore) VerifyRequestUser(r *http.Request) *UserAccount {
	// Allow localhost desktop GUI requests without token as admin
	remoteHost := strings.Split(r.RemoteAddr, ":")[0]
	tok := r.Header.Get("X-Auth-Token")
	if tok == "" {
		if c, err := r.Cookie("almino_token"); err == nil {
			tok = c.Value
		}
	}
	if tok == "" && (remoteHost == "127.0.0.1" || remoteHost == "::1") && r.URL.Path == "/api/v1/devices/bind" {
		return s.GetUser("mina")
	}
	parts := strings.SplitN(tok, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	u := s.GetUser(parts[0])
	if u == nil {
		return nil
	}
	expected := makeAuthToken(u.Username, u.Password)
	if tok != expected {
		return nil
	}
	return u
}

func (s *DeviceStore) BindDevice(payload map[string]interface{}) (*DeviceRecord, error) {
	res, err := s.pool.DBBind(s.dbPath, payload)
	if err != nil {
		return nil, err
	}
	tokenKey := getStringField(res, "token_key")
	devID := toInt64(res["id"])
	email := strings.ToLower(strings.TrimSpace(getStringField(payload, "email")))
	owner := strings.ToLower(strings.TrimSpace(getStringField(payload, "owner_user")))
	if owner == "" {
		owner = "mina"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, exists := s.byEmail[email]
	if !exists {
		rec = &DeviceRecord{
			ID:        devID,
			Email:     email,
			TokenKey:  tokenKey,
			CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
			Status:    "ACTIVE",
			OwnerUser: owner,
		}
		s.ordered = append([]*DeviceRecord{rec}, s.ordered...)
	}
	rec.ID = devID
	rec.TokenKey = tokenKey
	rec.Password = getStringField(payload, "password")
	rec.Phone = getStringField(payload, "phone")
	rec.ADSID = getStringField(payload, "adsid")
	rec.TOTPSecret = getStringField(payload, "totp_secret")
	rec.AdiPbB64 = getStringField(payload, "adi_pb_b64")
	rec.HostUUID = getStringField(payload, "host_uuid")
	rec.UDID = getStringField(payload, "udid")
	rec.MID = getStringField(payload, "mid")
	rec.RoutingData = getStringField(payload, "routing_data")
	rec.LocalUserUUID = getStringField(payload, "local_user_uuid")
	rec.SerialNumber = getStringField(payload, "serial_number")
	rec.ClientInfo = getStringField(payload, "client_info")
	rec.ServerModel = getStringField(payload, "server_model")
	rec.OwnerUser = owner
	if rec.ServerModel == "" {
		rec.ServerModel = "MacBookPro15,1"
	}

	s.byToken[tokenKey] = rec
	s.byEmail[email] = rec
	s.byID[devID] = rec
	return rec, nil
}

func (s *DeviceStore) GetByTokenOrEmail(key string) *DeviceRecord {
	k := strings.TrimSpace(key)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.byToken[k]; ok {
		return r
	}
	if strings.HasPrefix(k, "NotactiveE_") {
		alt := "AlMino_" + strings.TrimPrefix(k, "NotactiveE_")
		if r, ok := s.byToken[alt]; ok {
			return r
		}
	} else if !strings.Contains(k, "_") && !strings.Contains(k, "@") {
		if r, ok := s.byToken["AlMino_"+k]; ok {
			return r
		}
	}
	if r, ok := s.byEmail[strings.ToLower(k)]; ok {
		return r
	}
	return nil
}

func (s *DeviceStore) GetByID(id int64) *DeviceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byID[id]
}

func (s *DeviceStore) ResolveLiveCode(rec *DeviceRecord) (code string, rem int, source string) {
	now := time.Now().Unix()
	rem = int(30 - (now % 30))
	if rec == nil {
		return "", rem, "NOT_FOUND"
	}
	if rec.AdiPbB64 != "" && rec.HostUUID != "" {
		if out, err := s.pool.GenerateOTPCode(rec.AdiPbB64, rec.HostUUID); err == nil && out.Code != "" {
			return out.Code, out.RemainingSeconds, "APPLE_ADI_VIRTUAL_MAC"
		}
	}
	if rec.TOTPSecret != "" {
		c, r, _ := ComputeTOTP(rec.TOTPSecret, 30, 6, "sha1", float64(now))
		return c, r, "TOTP_RFC6238"
	}
	if rec.LastCode != "" {
		return rec.LastCode, rem, "PUSHED_CODE"
	}
	return "", rem, "WAITING_FOR_SECRET_OR_CODE"
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || strings.Contains(r.Host, "onrender.com") || strings.Contains(r.Host, "al-mino.site") {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "127.0.0.1:8820"
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func main() {
	defaultPort := 8820
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			defaultPort = p
		}
	}
	port := flag.Int("port", defaultPort, "HTTP server port")
	workers := flag.Int("workers", 4, "Number of parallel ADI Unicorn worker processes")
	prewarm := flag.Int("prewarm", 5, "Number of pre-provisioned virtual MacBook Pros to keep ready in RAM")
	pythonCmd := flag.String("python", "python", "Python executable for ADI Unicorn RPC workers")
	flag.Parse()

	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)
	if _, err := os.Stat(filepath.Join(baseDir, "adi_rpc_worker.py")); err != nil {
		cwd, _ := os.Getwd()
		if _, err2 := os.Stat(filepath.Join(cwd, "adi_rpc_worker.py")); err2 == nil {
			baseDir = cwd
		} else if _, err3 := os.Stat(filepath.Join(filepath.Dir(cwd), "adi_rpc_worker.py")); err3 == nil {
			baseDir = filepath.Dir(cwd)
		}
	}

	workerScript := filepath.Join(baseDir, "adi_rpc_worker.py")
	dbPath := filepath.Join(baseDir, "mac_auth_system.db")
	savedLinkedPath := filepath.Join(baseDir, "linked_mac_accounts.txt")

	fmt.Printf("========================================================================\n")
	fmt.Printf(" 🚀 Al Mino (al-mino.site) — Apple Mac Linker & 2FA Cloud (Golang)\n")
	fmt.Printf("========================================================================\n")
	fmt.Printf(" [*] Base Directory : %s\n", baseDir)
	fmt.Printf(" [*] Starting %d parallel ADI Unicorn worker processes...\n", *workers)

	pool, err := NewAdiEnginePool(*pythonCmd, workerScript, baseDir, *workers, *prewarm)
	if err != nil {
		fmt.Printf(" [!] Failed to initialize ADI worker pool: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(" [+] ADI Multi-Process Worker Pool Ready (%d processes, Pre-warm pool=%d)!\n", len(pool.workers), *prewarm)

	store, err := NewDeviceStore(dbPath, pool)
	if err != nil {
		fmt.Printf(" [!] Failed to load mac_auth_system.db: %v\n", err)
		os.Exit(1)
	}
	linker := NewLinkerManager(pool, store, savedLinkedPath)

	store.mu.RLock()
	loadedCount := 0
	for _, rec := range store.ordered {
		if rec.AdiPbB64 != "" && rec.HostUUID != "" {
			linker.jobs = append(linker.jobs, &AccountJob{
				ID:         len(linker.jobs) + 1,
				Email:      rec.Email,
				Password:   rec.Password,
				Phone:      rec.Phone,
				Status:     "✅ LINKED (MacBook Pro)",
				StatusHex:  "#3fb950",
				SMSCode:    "-",
				LiveCode:   "...",
				GetCodeURL: fmt.Sprintf("http://127.0.0.1:%d/getcode/%s", *port, rec.TokenKey),
				TokenKey:   rec.TokenKey,
				PbB64:      rec.AdiPbB64,
				HostUUID:   rec.HostUUID,
				OwnerUser:  rec.OwnerUser,
			})
			loadedCount++
		}
	}
	store.mu.RUnlock()
	linker.AppendLog(fmt.Sprintf("[+] Go Engine Ready! Loaded %d linked MacBook Pro account(s) from vault.", loadedCount))

	mux := http.NewServeMux()

	// 1. Main Web Linker Studio UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/linker" && r.URL.Path != "/dashboard" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(webStudioHTML))
	})

	// 2. Auth Login Endpoint
	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		u := store.AuthenticateUser(req.Username, req.Password)
		if u == nil {
			writeJSON(w, 401, map[string]interface{}{"ok": false, "error": "Invalid username or password"})
			return
		}
		tok := makeAuthToken(u.Username, u.Password)
		http.SetCookie(w, &http.Cookie{
			Name:     "almino_token",
			Value:    tok,
			Path:     "/",
			MaxAge:   86400 * 30,
			HttpOnly: false,
		})
		writeJSON(w, 200, map[string]interface{}{
			"ok":       true,
			"token":    tok,
			"username": u.Username,
			"role":     u.Role,
			"credits":  u.Credits,
		})
	})

	// 3. Admin Users Management Endpoints
	mux.HandleFunc("/api/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		u := store.VerifyRequestUser(r)
		if u == nil || u.Role != "ADMIN" {
			writeJSON(w, 403, map[string]interface{}{"error": "Admin access required"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "users": store.ListUsers()})
	})

	mux.HandleFunc("/api/v1/admin/users/upsert", func(w http.ResponseWriter, r *http.Request) {
		u := store.VerifyRequestUser(r)
		if u == nil || u.Role != "ADMIN" {
			writeJSON(w, 403, map[string]interface{}{"error": "Admin access required"})
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
			Credits  int64  `json:"credits"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := store.UpsertUser(req.Username, req.Password, req.Role, req.Credits); err != nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "users": store.ListUsers()})
	})

	mux.HandleFunc("/api/v1/admin/users/delete", func(w http.ResponseWriter, r *http.Request) {
		u := store.VerifyRequestUser(r)
		if u == nil || u.Role != "ADMIN" {
			writeJSON(w, 403, map[string]interface{}{"error": "Admin access required"})
			return
		}
		var req struct {
			Username string `json:"username"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := store.DeleteUser(req.Username); err != nil {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "users": store.ListUsers()})
	})

	// 4. PUBLIC GET /api/getcode/{token_key}
	mux.HandleFunc("/api/getcode/", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.URL.Path, "/api/getcode/")
		rec := store.GetByTokenOrEmail(tok)
		if rec == nil {
			writeJSON(w, 404, map[string]interface{}{"status": "error", "message": "Token not found"})
			return
		}
		code, rem, src := store.ResolveLiveCode(rec)
		writeJSON(w, 200, map[string]interface{}{
			"status":            "ok",
			"id":                rec.ID,
			"email":             rec.Email,
			"token_key":         rec.TokenKey,
			"code":              code,
			"text":              fmt.Sprintf("AppleID 登录验证码:%s", code),
			"remaining_seconds": rem,
			"period":            30,
			"source":            src,
		})
	})

	// 5. PUBLIC GET /getcode/{token_key}
	mux.HandleFunc("/getcode/", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.URL.Path, "/getcode/")
		rec := store.GetByTokenOrEmail(tok)
		if rec == nil {
			http.Error(w, "Error: Invalid or unknown token", 404)
			return
		}
		code, rem, src := store.ResolveLiveCode(rec)
		fmtParam := strings.ToLower(r.URL.Query().Get("format"))
		accept := strings.ToLower(r.Header.Get("Accept"))
		ua := strings.ToLower(r.Header.Get("User-Agent"))
		wantsHTML := fmtParam == "html" || (fmtParam == "" && strings.Contains(accept, "text/html") && (strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") || strings.Contains(ua, "safari") || strings.Contains(ua, "edg")))

		if !wantsHTML {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			if code != "" {
				_, _ = w.Write([]byte(fmt.Sprintf("AppleID 登录验证码:%s", code)))
			} else {
				_, _ = w.Write([]byte("Error: No TOTP secret or code configured for this account yet"))
			}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(renderGetCodeHTML(rec, code, rem, src)))
	})

	// 6. PUBLIC GET /api/free/v4/getcode?id=X
	mux.HandleFunc("/api/free/v4/getcode", func(w http.ResponseWriter, r *http.Request) {
		idVal, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		rec := store.GetByID(idVal)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if rec == nil {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("Error: Device ID not found"))
			return
		}
		code, _, _ := store.ResolveLiveCode(rec)
		if code != "" {
			_, _ = w.Write([]byte(fmt.Sprintf("AppleID 登录验证码:%s", code)))
		} else {
			_, _ = w.Write([]byte("Error: No TOTP secret configured"))
		}
	})

	// 7. POST /api/v1/devices/bind & GET /api/v1/devices
	mux.HandleFunc("/api/v1/devices/bind", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeJSON(w, 405, map[string]string{"error": "Method not allowed"})
			return
		}
		u := store.VerifyRequestUser(r)
		if u == nil {
			writeJSON(w, 401, map[string]string{"error": "Authentication required"})
			return
		}
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if payload["owner_user"] == nil || payload["owner_user"] == "" {
			payload["owner_user"] = u.Username
		}
		rec, err := store.BindDevice(payload)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		code, rem, _ := store.ResolveLiveCode(rec)
		base := requestBaseURL(r)
		writeJSON(w, 200, map[string]interface{}{
			"status":            "bound",
			"id":                rec.ID,
			"email":             rec.Email,
			"token_key":         rec.TokenKey,
			"current_code":      code,
			"remaining_seconds": rem,
			"getcode_url":       fmt.Sprintf("%s/getcode/%s", base, rec.TokenKey),
			"legacy_url":        fmt.Sprintf("%s/api/free/v4/getcode?id=%d", base, rec.ID),
		})
	})

	mux.HandleFunc("/api/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{"status": "online"})
	})

	mux.HandleFunc("/api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		u := store.VerifyRequestUser(r)
		if u == nil {
			writeJSON(w, 401, map[string]string{"error": "Authentication required"})
			return
		}
		base := requestBaseURL(r)
		store.mu.RLock()
		list := make([]map[string]interface{}, 0, len(store.ordered))
		for i, rec := range store.ordered {
			if u.Role != "ADMIN" && !strings.EqualFold(rec.OwnerUser, u.Username) {
				continue
			}
			if i >= 200 {
				break
			}
			code, rem, src := store.ResolveLiveCode(rec)
			list = append(list, map[string]interface{}{
				"id":                rec.ID,
				"email":             rec.Email,
				"phone":             rec.Phone,
				"token_key":         rec.TokenKey,
				"live_code":         code,
				"remaining_seconds": rem,
				"code_source":       src,
				"getcode_url":       fmt.Sprintf("%s/getcode/%s", base, rec.TokenKey),
			})
		}
		store.mu.RUnlock()
		writeJSON(w, 200, map[string]interface{}{"devices": list})
	})

	// 8. Protected Web Linker Studio API Endpoints
	mux.HandleFunc("/api/v1/linker/state", func(w http.ResponseWriter, r *http.Request) {
		u := store.VerifyRequestUser(r)
		if u == nil {
			writeJSON(w, 401, map[string]interface{}{"error": "Unauthorized"})
			return
		}
		base := requestBaseURL(r)
		isAdmin := (u.Role == "ADMIN")
		linker.mu.RLock()
		jobsCopy := make([]AccountJob, 0, len(linker.jobs))
		linkedCount := 0
		failedCount := 0
		for _, j := range linker.jobs {
			if !isAdmin && !strings.EqualFold(j.OwnerUser, u.Username) {
				continue
			}
			jc := *j
			if strings.Contains(jc.Status, "LINKED") {
				linkedCount++
				if jc.TokenKey != "" {
					jc.GetCodeURL = fmt.Sprintf("%s/getcode/%s", base, jc.TokenKey)
				}
				if jc.PbB64 != "" && jc.HostUUID != "" {
					if out, err := pool.GenerateOTPCode(jc.PbB64, jc.HostUUID); err == nil {
						jc.LiveCode = fmt.Sprintf("%s (%ds)", out.Code, out.RemainingSeconds)
					}
				}
			} else if strings.Contains(jc.Status, "❌") {
				failedCount++
			}
			jc.PbB64 = ""
			jobsCopy = append(jobsCopy, jc)
		}
		logsCopy := append([]string(nil), linker.logs...)
		linker.mu.RUnlock()

		writeJSON(w, 200, map[string]interface{}{
			"user":              u.Username,
			"role":              u.Role,
			"credits":           u.Credits,
			"running":           linker.running.Load(),
			"active_goroutines": linker.activeGorouts.Load(),
			"prewarmed_macs":    len(pool.macPool),
			"total":             len(jobsCopy),
			"linked":            linkedCount,
			"failed":            failedCount,
			"jobs":              jobsCopy,
			"logs":              logsCopy,
		})
	})

	mux.HandleFunc("/api/v1/linker/add", func(w http.ResponseWriter, r *http.Request) {
		u := store.VerifyRequestUser(r)
		if u == nil {
			writeJSON(w, 401, map[string]interface{}{"error": "Unauthorized"})
			return
		}
		var req struct {
			RawText string `json:"raw_text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		parsed := ParseAccountsText(req.RawText)
		added := linker.AddAccounts(parsed, u.Username)
		linker.AppendLog(fmt.Sprintf("[+] [%s] Added %d account(s) to queue.", u.Username, added))
		writeJSON(w, 200, map[string]interface{}{"ok": true, "parsed": len(parsed), "added": added})
	})

	mux.HandleFunc("/api/v1/linker/start", func(w http.ResponseWriter, r *http.Request) {
		u := store.VerifyRequestUser(r)
		if u == nil {
			writeJSON(w, 401, map[string]interface{}{"error": "Unauthorized"})
			return
		}
		if !store.HasCredits(u.Username) {
			writeJSON(w, 403, map[string]interface{}{"ok": false, "error": "No credits remaining"})
			return
		}
		var req struct {
			Threads    int    `json:"threads"`
			SMSTimeout int    `json:"sms_timeout"`
			RawText    string `json:"raw_text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.TrimSpace(req.RawText) != "" {
			parsed := ParseAccountsText(req.RawText)
			linker.AddAccounts(parsed, u.Username)
		}
		count := linker.StartBatch(req.Threads, req.SMSTimeout, requestBaseURL(r), u.Username, u.Role == "ADMIN")
		writeJSON(w, 200, map[string]interface{}{"ok": true, "started": count})
	})

	mux.HandleFunc("/api/v1/linker/stop", func(w http.ResponseWriter, r *http.Request) {
		u := store.VerifyRequestUser(r)
		if u == nil {
			writeJSON(w, 401, map[string]interface{}{"error": "Unauthorized"})
			return
		}
		linker.stopFlag.Store(true)
		linker.AppendLog(fmt.Sprintf("[!] [%s] Stop signal sent to active Goroutines...", u.Username))
		writeJSON(w, 200, map[string]interface{}{"ok": true})
	})

	mux.HandleFunc("/api/v1/linker/retry", func(w http.ResponseWriter, r *http.Request) {
		u := store.VerifyRequestUser(r)
		if u == nil {
			writeJSON(w, 401, map[string]interface{}{"error": "Unauthorized"})
			return
		}
		var req struct {
			Threads    int `json:"threads"`
			SMSTimeout int `json:"sms_timeout"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		isAdmin := (u.Role == "ADMIN")
		linker.mu.Lock()
		retried := 0
		for _, j := range linker.jobs {
			if (isAdmin || strings.EqualFold(j.OwnerUser, u.Username)) && strings.Contains(j.Status, "❌") {
				j.Status = "Pending"
				j.StatusHex = "#e6edf3"
				retried++
			}
		}
		linker.mu.Unlock()
		if retried > 0 {
			linker.StartBatch(req.Threads, req.SMSTimeout, requestBaseURL(r), u.Username, isAdmin)
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "retried": retried})
	})

	mux.HandleFunc("/api/v1/linker/clear", func(w http.ResponseWriter, r *http.Request) {
		u := store.VerifyRequestUser(r)
		if u == nil {
			writeJSON(w, 401, map[string]interface{}{"error": "Unauthorized"})
			return
		}
		isAdmin := (u.Role == "ADMIN")
		linker.mu.Lock()
		if isAdmin {
			linker.jobs = nil
		} else {
			var kept []*AccountJob
			for _, j := range linker.jobs {
				if !strings.EqualFold(j.OwnerUser, u.Username) {
					kept = append(kept, j)
				}
			}
			linker.jobs = kept
		}
		linker.mu.Unlock()
		linker.AppendLog(fmt.Sprintf("[*] [%s] Cleared table.", u.Username))
		writeJSON(w, 200, map[string]interface{}{"ok": true})
	})

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	fmt.Printf(" [+] Server listening on http://127.0.0.1:%d (and all network interfaces)\n", *port)
	fmt.Printf("========================================================================\n")

	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		for {
			time.Sleep(10 * time.Minute)
			extURL := os.Getenv("RENDER_EXTERNAL_URL")
			if extURL == "" {
				extURL = "https://almino-app.onrender.com"
			}
			_, _ = client.Get(strings.TrimRight(extURL, "/") + "/api/v1/ping")
		}
	}()

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Printf(" [!] HTTP server error: %v\n", err)
		os.Exit(1)
	}
}
