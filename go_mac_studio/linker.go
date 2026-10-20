package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultClientInfo = "<MacBookPro15,1> <Mac OS X;10.15.7;19H15> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
	DefaultUserAgent  = "Xcode"
)

type GSAProfile struct {
	Name       string
	ClientInfo string
	UserAgent  string
}

var gsaProfiles = []GSAProfile{
	{
		Name:       "Mac_Catalina_akd",
		ClientInfo: DefaultClientInfo,
		UserAgent:  "Xcode",
	},
	{
		Name:       "Mac_CommerceKit",
		ClientInfo: "<MacBookPro15,1> <Mac OS X;10.15.7;19H15> <com.apple.CommerceKit/1.0 (com.apple.appstoreagent/1.0)>",
		UserAgent:  "appstoreagent/1.0 CFNetwork/1128.0.1 Darwin/19.6.0",
	},
	{
		Name:       "AuthKitWin_iTunes",
		ClientInfo: "<PC> <Windows;10.0.19045;0> <com.apple.AuthKitWin/1 (com.apple.iCloud/15.0)>",
		UserAgent:  "akd/1.0 CFNetwork/808.2.16 Darwin/16.3.0",
	},
}

func newInsecureHTTPClient(timeout time.Duration) *http.Client {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        2000,
		MaxIdleConnsPerHost: 500,
		IdleConnTimeout:     30 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Jar:       jar,
		Timeout:   timeout,
	}
}

func newUUIDv4Upper() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return strings.ToUpper(fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

func buildCPD(dev *VirtualMacDevice, svct string) map[string]interface{} {
	nowISO := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	return map[string]interface{}{
		"bootstrap":             true,
		"icscrec":               true,
		"pbe":                   false,
		"prkgen":                true,
		"ckgen":                 true,
		"svct":                  svct,
		"X-Apple-I-Client-Time": nowISO,
		"X-Apple-I-TimeZone":    "UTC",
		"loc":                   "en_US",
		"X-Apple-Locale":        "en_US",
		"X-Apple-I-MD":          dev.MD,
		"X-Apple-I-MD-M":        dev.MDM,
		"X-Apple-I-MD-LU":       dev.LocalUserUUID,
		"X-Apple-I-MD-RINFO":    dev.RoutingData,
		"X-Mme-Device-Id":       dev.UDID,
		"X-Apple-I-SRL-NO":      dev.SerialNumber,
	}
}

func checkAndSyncSIM(pool *AdiEnginePool, respHeaders http.Header, respDict map[string]interface{}, dev *VirtualMacDevice) {
	simB64 := ""
	if respHeaders != nil {
		simB64 = respHeaders.Get("X-Apple-I-MD-DATA")
		if simB64 == "" {
			simB64 = respHeaders.Get("x-apple-i-md-data")
		}
	}
	if simB64 == "" && respDict != nil {
		if v, ok := respDict["sim"]; ok {
			switch tv := v.(type) {
			case []byte:
				simB64 = base64.StdEncoding.EncodeToString(tv)
			case string:
				simB64 = tv
			}
		}
		if simB64 == "" {
			if st, ok := respDict["Status"].(map[string]interface{}); ok {
				if v, ok := st["sim"]; ok {
					switch tv := v.(type) {
					case []byte:
						simB64 = base64.StdEncoding.EncodeToString(tv)
					case string:
						simB64 = tv
					}
				}
			}
		}
	}
	if simB64 != "" {
		_ = pool.SyncMachine(dev, simB64)
	}
}

func gsaPost(pool *AdiEnginePool, client *http.Client, params map[string]interface{}, dev *VirtualMacDevice, svct string, prof GSAProfile) (map[string]interface{}, map[string]interface{}) {
	_ = pool.RefreshAnisette(dev)
	cpd := buildCPD(dev, svct)
	reqDict := map[string]interface{}{
		"cpd": cpd,
	}
	for k, v := range params {
		reqDict[k] = v
	}
	body := map[string]interface{}{
		"Header":  map[string]interface{}{"Version": "1.0.1"},
		"Request": reqDict,
	}
	xmlBytes := BuildPlistXML(body)

	req, err := http.NewRequest("POST", "https://gsa.apple.com/grandslam/GsService2", bytes.NewReader(xmlBytes))
	if err != nil {
		return map[string]interface{}{"Status": map[string]interface{}{"hsc": int64(500), "em": err.Error()}}, cpd
	}
	req.Header.Set("Content-Type", "text/x-xml-plist")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", prof.UserAgent)
	req.Header.Set("X-MMe-Client-Info", prof.ClientInfo)

	headerKeys := []string{
		"X-Apple-I-Client-Time",
		"X-Apple-I-TimeZone",
		"X-Apple-Locale",
		"X-Apple-I-MD",
		"X-Apple-I-MD-M",
		"X-Apple-I-MD-LU",
		"X-Apple-I-MD-RINFO",
		"X-Mme-Device-Id",
		"X-Apple-I-SRL-NO",
	}
	for _, k := range headerKeys {
		if val, ok := cpd[k]; ok && fmt.Sprintf("%v", val) != "" {
			req.Header.Set(k, fmt.Sprintf("%v", val))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return map[string]interface{}{"Status": map[string]interface{}{"hsc": int64(500), "em": err.Error()}}, cpd
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return map[string]interface{}{"Status": map[string]interface{}{"hsc": int64(resp.StatusCode), "em": string(respBytes)}}, cpd
	}
	parsed, err := ParsePlistBytes(respBytes)
	if err != nil {
		return map[string]interface{}{"Status": map[string]interface{}{"hsc": int64(resp.StatusCode), "em": err.Error()}}, cpd
	}
	respDict, _ := parsed["Response"].(map[string]interface{})
	if respDict == nil {
		respDict = parsed
	}
	checkAndSyncSIM(pool, resp.Header, respDict, dev)
	return respDict, cpd
}

func runSRPLogin(pool *AdiEnginePool, client *http.Client, email, password string, dev *VirtualMacDevice, svct string) (map[string]interface{}, map[string]interface{}, map[string]interface{}) {
	var lastInit map[string]interface{}
	var lastCPD map[string]interface{}

	for _, prof := range gsaProfiles {
		usr, A, err := NewSRPUser(email)
		if err != nil {
			continue
		}
		initParams := map[string]interface{}{
			"A2k": A,
			"ps":  []string{"s2k", "s2k_fo"},
			"u":   email,
			"o":   "init",
		}
		rInit, cpd := gsaPost(pool, client, initParams, dev, svct, prof)
		lastInit, lastCPD = rInit, cpd

		sp, hasSP := rInit["sp"].(string)
		if !hasSP || sp == "" {
			continue
		}
		saltBytes, _ := rInit["s"].([]byte)
		bBytes, _ := rInit["B"].([]byte)
		iterInt := int(toInt64(rInit["i"]))
		cVal := fmt.Sprintf("%v", rInit["c"])

		usr.Password = EncryptApplePassword(password, saltBytes, iterInt, sp)
		M1, err := usr.ProcessChallenge(saltBytes, bBytes)
		if err != nil {
			continue
		}

		compParams := map[string]interface{}{
			"c":  cVal,
			"M1": M1,
			"u":  email,
			"o":  "complete",
		}
		rComp, cpd2 := gsaPost(pool, client, compParams, dev, svct, prof)
		var spdDict map[string]interface{}
		if spdRaw, ok := rComp["spd"].([]byte); ok && len(spdRaw) > 0 {
			if dec, err := usr.DecryptSPD(spdRaw); err == nil {
				spdDict = dec
				checkAndSyncSIM(pool, nil, spdDict, dev)
			}
		}
		return rComp, spdDict, cpd2
	}
	return lastInit, nil, lastCPD
}

func buildGSAAuthHeaders(pool *AdiEnginePool, identityToken string, ap map[string]string, dev *VirtualMacDevice, cpd map[string]interface{}, isJSON bool) map[string]string {
	_ = pool.RefreshAnisette(dev)
	nowISO := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	cpd["X-Apple-I-MD-M"] = dev.MDM
	cpd["X-Apple-I-MD"] = dev.MD
	cpd["X-Apple-I-Client-Time"] = nowISO

	ct := "text/x-xml-plist"
	if isJSON {
		ct = "application/json"
	}
	h := map[string]string{
		"Content-Type":           ct,
		"Accept":                 ct,
		"Accept-Language":        "en-us",
		"User-Agent":             ap["User-Agent"],
		"X-Apple-Identity-Token": identityToken,
		"X-Apple-App-Info":       ap["X-Apple-App-Info"],
		"X-Mme-Client-Info":      ap["X-Mme-Client-Info"],
	}
	if xv := ap["X-Xcode-Version"]; xv != "" {
		h["X-Xcode-Version"] = xv
	}
	copyKeys := []string{
		"X-Apple-I-Client-Time",
		"X-Apple-I-TimeZone",
		"loc",
		"X-Apple-Locale",
		"X-Apple-I-MD",
		"X-Apple-I-MD-M",
		"X-Apple-I-MD-LU",
		"X-Apple-I-MD-RINFO",
		"X-Mme-Device-Id",
		"X-Apple-I-SRL-NO",
	}
	for _, k := range copyKeys {
		if v, ok := cpd[k]; ok && fmt.Sprintf("%v", v) != "" {
			h[k] = fmt.Sprintf("%v", v)
		}
	}
	return h
}

func triggerSMS2FA(pool *AdiEnginePool, sessClient *http.Client, spdDict map[string]interface{}, dev *VirtualMacDevice, cpd map[string]interface{}, phoneID int, forcePut bool) bool {
	adsid := getStringField(spdDict, "adsid")
	if adsid == "" {
		adsid = getStringField(spdDict, "DsPrsId")
	}
	idmsToken := getStringField(spdDict, "GsIdmsToken")
	if adsid == "" || idmsToken == "" {
		return false
	}
	identityToken := base64.StdEncoding.EncodeToString([]byte(adsid + ":" + idmsToken))
	ap := map[string]string{
		"label":             "Xcode_AOSKit",
		"User-Agent":        "Xcode",
		"X-Apple-App-Info":  "com.apple.gs.xcode.auth",
		"X-Xcode-Version":   "11.2 (11B41)",
		"X-Mme-Client-Info": DefaultClientInfo,
	}

	dev.SMSError = ""
	if !forcePut {
		hAuth := buildGSAAuthHeaders(pool, identityToken, ap, dev, cpd, true)
		hAuth["Accept"] = "application/json, text/x-xml-plist, text/html, */*"
		req, err := http.NewRequest("GET", "https://gsa.apple.com/auth", nil)
		if err == nil {
			for k, v := range hAuth {
				req.Header.Set(k, v)
			}
			if resp, err := sessClient.Do(req); err == nil {
				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				checkAndSyncSIM(pool, resp.Header, nil, dev)
				bodyLow := strings.ToLower(string(bodyBytes))
				if strings.Contains(bodyLow, "can't be sent") || strings.Contains(bodyLow, "cannot be sent") || strings.Contains(bodyLow, "try again later") || strings.Contains(bodyLow, "-28043") {
					dev.SMSError = "Phone rate-limited by Apple (try again later)"
					return false
				}
				if resp.StatusCode == 201 {
					return true
				}
			}
		}
	}

	hPut := buildGSAAuthHeaders(pool, identityToken, ap, dev, cpd, true)
	putBody, _ := json.Marshal(map[string]interface{}{
		"phoneNumber": map[string]interface{}{"id": phoneID},
		"mode":        "sms",
	})
	reqPut, err := http.NewRequest("PUT", "https://gsa.apple.com/auth/verify/phone", bytes.NewReader(putBody))
	if err != nil {
		return false
	}
	for k, v := range hPut {
		reqPut.Header.Set(k, v)
	}
	respPut, err := sessClient.Do(reqPut)
	if err != nil {
		return false
	}
	putRespBytes, _ := io.ReadAll(respPut.Body)
	respPut.Body.Close()
	checkAndSyncSIM(pool, respPut.Header, nil, dev)
	putLow := strings.ToLower(string(putRespBytes))
	if strings.Contains(putLow, "can't be sent") || strings.Contains(putLow, "cannot be sent") || strings.Contains(putLow, "try again later") || strings.Contains(putLow, "-28043") || respPut.StatusCode == 400 || respPut.StatusCode == 403 || respPut.StatusCode == 429 || respPut.StatusCode == 503 {
		dev.SMSError = fmt.Sprintf("Apple refused SMS to phone (HTTP %d)", respPut.StatusCode)
		return false
	}
	return respPut.StatusCode == 200 || respPut.StatusCode == 201 || respPut.StatusCode == 202 || respPut.StatusCode == 204
}

func validate2FACode(pool *AdiEnginePool, sessClient *http.Client, code string, spdDict map[string]interface{}, dev *VirtualMacDevice, cpd map[string]interface{}, isSMS bool, phoneID int) bool {
	var dsidCandidates []string
	if s := getStringField(spdDict, "adsid"); s != "" {
		dsidCandidates = append(dsidCandidates, s)
	}
	if s := getStringField(spdDict, "DsPrsId"); s != "" {
		dsidCandidates = append(dsidCandidates, s)
	}

	type tokPair struct {
		name string
		val  string
	}
	var tokenCandidates []tokPair
	if s := getStringField(spdDict, "GsIdmsToken"); s != "" {
		tokenCandidates = append(tokenCandidates, tokPair{"GsIdmsToken", s})
	}
	if tMap, ok := spdDict["t"].(map[string]interface{}); ok {
		if petMap, ok := tMap["com.apple.gs.idms.pet"].(map[string]interface{}); ok {
			if pet := getStringField(petMap, "token"); pet != "" {
				tokenCandidates = append(tokenCandidates, tokPair{"pet", pet})
			}
		}
	}

	apXcode := map[string]string{
		"label":             "Xcode_AOSKit",
		"User-Agent":        "Xcode",
		"X-Apple-App-Info":  "com.apple.gs.xcode.auth",
		"X-Xcode-Version":   "11.2 (11B41)",
		"X-Mme-Client-Info": DefaultClientInfo,
	}

	if isSMS && len(dsidCandidates) > 0 && len(tokenCandidates) > 0 {
		idTok := base64.StdEncoding.EncodeToString([]byte(dsidCandidates[0] + ":" + tokenCandidates[0].val))
		hSec := buildGSAAuthHeaders(pool, idTok, apXcode, dev, cpd, true)
		secBody, _ := json.Marshal(map[string]interface{}{
			"phoneNumber":  map[string]interface{}{"id": phoneID},
			"mode":         "sms",
			"securityCode": map[string]interface{}{"code": strings.TrimSpace(code)},
		})
		if req, err := http.NewRequest("POST", "https://gsa.apple.com/auth/verify/phone/securitycode", bytes.NewReader(secBody)); err == nil {
			for k, v := range hSec {
				req.Header.Set(k, v)
			}
			if resp, err := sessClient.Do(req); err == nil {
				_, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
				checkAndSyncSIM(pool, resp.Header, nil, dev)
				if pe := resp.Header.Get("X-Apple-PE-Token"); pe != "" {
					dev.PEToken = pe
				}
				if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 204 {
					return true
				}
			}
		}
	}

	appProfiles := []map[string]string{
		apXcode,
		{
			"label":             "iTunes_Auth",
			"User-Agent":        DefaultUserAgent,
			"X-Apple-App-Info":  "com.apple.gs.itunes.auth",
			"X-Mme-Client-Info": DefaultClientInfo,
		},
		{
			"label":             "idms_Auth",
			"User-Agent":        DefaultUserAgent,
			"X-Apple-App-Info":  "com.apple.gs.idms.auth",
			"X-Mme-Client-Info": DefaultClientInfo,
		},
	}

	for _, dsid := range dsidCandidates {
		for _, tc := range tokenCandidates {
			idTok := base64.StdEncoding.EncodeToString([]byte(dsid + ":" + tc.val))
			for _, ap := range appProfiles {
				valHeaders := buildGSAAuthHeaders(pool, idTok, ap, dev, cpd, false)
				valHeaders["security-code"] = strings.TrimSpace(code)
				req, err := http.NewRequest("GET", "https://gsa.apple.com/grandslam/GsService2/validate", nil)
				if err != nil {
					continue
				}
				for k, v := range valHeaders {
					req.Header.Set(k, v)
				}
				resp, err := sessClient.Do(req)
				if err != nil {
					continue
				}
				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				checkAndSyncSIM(pool, resp.Header, nil, dev)
				if resp.StatusCode == 200 {
					if len(bodyBytes) > 0 {
						if valData, err := ParsePlistBytes(bodyBytes); err == nil {
							checkAndSyncSIM(pool, nil, valData, dev)
							ec := toInt64(valData["ec"])
							if st, ok := valData["Status"].(map[string]interface{}); ok && ec == 0 {
								ec = toInt64(st["ec"])
							}
							if ec == 0 {
								return true
							}
						}
					} else {
						return true
					}
				}
			}
		}
	}
	return false
}

func registerTrustedDevicePostdata(pool *AdiEnginePool, sessClient *http.Client, email, password string, spdDict map[string]interface{}, dev *VirtualMacDevice) map[string]interface{} {
	adsid := getStringField(spdDict, "adsid")
	if adsid == "" {
		adsid = getStringField(spdDict, "DsPrsId")
	}
	hbToken := ""
	if tMap, ok := spdDict["t"].(map[string]interface{}); ok {
		if hbMap, ok := tMap["com.apple.gs.idms.hb"].(map[string]interface{}); ok {
			hbToken = getStringField(hbMap, "token")
		}
	}
	if adsid == "" || hbToken == "" {
		return spdDict
	}

	_ = pool.RefreshAnisette(dev)
	urlSwitch := base64.StdEncoding.EncodeToString([]byte(adsid + ":postData"))
	hbB64 := base64.StdEncoding.EncodeToString([]byte(adsid + ":" + hbToken))
	ptknSum := sha256.Sum256([]byte(dev.UDID))
	ptkn := strings.ToUpper(hex.EncodeToString(ptknSum[:]))

	bodyPostdata := map[string]interface{}{
		"Header": map[string]interface{}{},
		"Request": map[string]interface{}{
			"cfuids":       []string{},
			"circleStatus": false,
			"dc":           "#9d9da0",
			"dn":           "MacBook Pro",
			"event":        "liveness",
			"loc":          "en_US",
			"prkgen":       true,
			"ptkn":         ptkn,
			"rep":          1,
			"services":     []string{"icloud", "itunesstore"},
			"sn":           dev.SerialNumber,
			"ut":           2,
		},
	}
	xmlBytes := BuildPlistXML(bodyPostdata)
	req, err := http.NewRequest("POST", "https://gsas.apple.com/grandslam/GsService2/postdata", bytes.NewReader(xmlBytes))
	if err != nil {
		return spdDict
	}
	req.Header.Set("Content-Type", "text/x-xml-plist")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("X-Apple-I-Device-Configuration-Mode", "0")
	req.Header.Set("X-Apple-I-UrlSwitch-Info", urlSwitch)
	req.Header.Set("X-Apple-HB-Token", hbB64)
	req.Header.Set("X-Mme-Device-Id", dev.UDID)
	req.Header.Set("X-MMe-Client-Info", DefaultClientInfo)
	req.Header.Set("X-Apple-I-DeviceUserMode", "0")
	req.Header.Set("X-Apple-I-MD-RINFO", dev.RoutingData)
	req.Header.Set("X-Apple-I-SRL-NO", dev.SerialNumber)
	req.Header.Set("X-Apple-I-MD-M", dev.MDM)
	req.Header.Set("X-Apple-I-MD", dev.MD)
	req.Header.Set("X-Apple-I-MD-LU", dev.LocalUserUUID)

	if resp, err := sessClient.Do(req); err == nil {
		respBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var pdDict map[string]interface{}
		if len(respBytes) > 0 {
			pdDict, _ = ParsePlistBytes(respBytes)
		}
		checkAndSyncSIM(pool, resp.Header, pdDict, dev)
	}

	// Final iTunes SRP pass so any postdata SIM sync is finalized
	_, spdFinal, _ := runSRPLogin(pool, sessClient, email, password, dev, "iTunes")
	if spdFinal != nil && toInt64(spdFinal["status-code"]) != 409 {
		return spdFinal
	}
	return spdDict
}

var (
	reISODate  = regexp.MustCompile(`\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}`)
	reSixDigit = regexp.MustCompile(`\b(\d{6})\b`)
	reEmail    = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	reURL      = regexp.MustCompile(`(?i)(https?://\S+)`)
	rePhone    = regexp.MustCompile(`^\+?\d{7,15}$`)
	reSplitSep = regexp.MustCompile(`[\t,|]+`)
)

func extractCodesFromSMSText(text string) []string {
	t := strings.TrimSpace(text)
	if t == "" || strings.HasPrefix(strings.ToLower(t), "no|") {
		return nil
	}
	cleaned := reISODate.ReplaceAllString(t, " ")
	matches := reSixDigit.FindAllStringSubmatch(cleaned, -1)
	var codes []string
	for _, m := range matches {
		if len(m) > 1 {
			codes = append(codes, m[1])
		}
	}
	return codes
}

type AccountJob struct {
	ID         int    `json:"id"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	Phone      string `json:"phone"`
	OTPUrl     string `json:"otp_url"`
	ManualCode string `json:"manual_code,omitempty"`
	Status     string `json:"status"`
	StatusHex  string `json:"status_hex"`
	SMSCode    string `json:"sms_code"`
	LiveCode   string `json:"live_code"`
	GetCodeURL string `json:"getcode_url"`
	TokenKey   string `json:"token_key"`
	PbB64      string `json:"adi_pb_b64,omitempty"`
	HostUUID   string `json:"host_uuid,omitempty"`
	OwnerUser  string `json:"owner_user,omitempty"`
}

func ParseAccountsText(rawText string) []*AccountJob {
	var lines []string
	for _, ln := range strings.Split(rawText, "\n") {
		s := strings.TrimSpace(ln)
		if s != "" {
			lines = append(lines, s)
		}
	}
	var results []*AccountJob
	i := 0
	for i < len(lines) {
		line := lines[i]
		if strings.ContainsAny(line, "\t,|") {
			otpURL := ""
			lineNoURL := line
			if loc := reURL.FindStringIndex(line); loc != nil {
				otpURL = strings.TrimSpace(line[loc[0]:loc[1]])
				lineNoURL = strings.TrimSpace(line[:loc[0]])
			}
			rawParts := reSplitSep.Split(lineNoURL, -1)
			var parts []string
			for _, p := range rawParts {
				if strings.TrimSpace(p) != "" {
					parts = append(parts, strings.TrimSpace(p))
				}
			}
			if len(parts) >= 2 && strings.Contains(parts[0], "@") {
				ph := ""
				if len(parts) >= 3 {
					ph = parts[2]
				}
				results = append(results, &AccountJob{
					Email:     parts[0],
					Password:  parts[1],
					Phone:     ph,
					OTPUrl:    otpURL,
					Status:    "Pending",
					StatusHex: "#e6edf3",
					SMSCode:   "-",
					LiveCode:  "-",
				})
				i++
				continue
			}
		}

		if strings.Contains(line, ":") && strings.Contains(strings.Split(line, ":")[0], "@") {
			otpURL := ""
			lineNoURL := line
			if loc := reURL.FindStringIndex(line); loc != nil {
				otpURL = strings.TrimSpace(line[loc[0]:loc[1]])
				lineNoURL = strings.TrimRight(line[:loc[0]], ": \t,")
			}
			rawParts := strings.Split(lineNoURL, ":")
			var parts []string
			for _, p := range rawParts {
				if strings.TrimSpace(p) != "" {
					parts = append(parts, strings.TrimSpace(p))
				}
			}
			if len(parts) >= 2 {
				ph := ""
				if len(parts) >= 3 {
					ph = parts[2]
				}
				results = append(results, &AccountJob{
					Email:     parts[0],
					Password:  parts[1],
					Phone:     ph,
					OTPUrl:    otpURL,
					Status:    "Pending",
					StatusHex: "#e6edf3",
					SMSCode:   "-",
					LiveCode:  "-",
				})
				i++
				continue
			}
		}

		if reEmail.MatchString(line) && i+1 < len(lines) {
			email := line
			password := strings.TrimSpace(lines[i+1])
			phone := ""
			otpURL := ""
			step := 2
			if i+2 < len(lines) {
				third := strings.TrimSpace(lines[i+2])
				if !reEmail.MatchString(third) {
					if loc := reURL.FindStringIndex(third); loc != nil {
						otpURL = strings.TrimSpace(third[loc[0]:loc[1]])
						before := strings.Trim(third[:loc[0]], " \t,:")
						if before != "" {
							phone = before
						}
						step = 3
					} else if rePhone.MatchString(third) {
						phone = third
						step = 3
						if i+3 < len(lines) {
							if m := reURL.FindString(lines[i+3]); m != "" {
								otpURL = strings.TrimSpace(m)
								step = 4
							}
						}
					}
				}
			}
			results = append(results, &AccountJob{
				Email:     email,
				Password:  password,
				Phone:     phone,
				OTPUrl:    otpURL,
				Status:    "Pending",
				StatusHex: "#e6edf3",
				SMSCode:   "-",
				LiveCode:  "-",
			})
			i += step
			continue
		}
		i++
	}
	return results
}

type LinkerManager struct {
	mu             sync.RWMutex
	jobs           []*AccountJob
	logs           []string
	running        atomic.Bool
	stopFlag       atomic.Bool
	activeGorouts  atomic.Int64
	pool           *AdiEnginePool
	store          *DeviceStore
	savedFilePath  string
	savedFileMutex sync.Mutex
}

func NewLinkerManager(pool *AdiEnginePool, store *DeviceStore, savedFilePath string) *LinkerManager {
	return &LinkerManager{
		pool:          pool,
		store:         store,
		savedFilePath: savedFilePath,
	}
}

func (m *LinkerManager) AppendLog(msg string) {
	ts := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] %s", ts, msg)
	m.mu.Lock()
	m.logs = append(m.logs, line)
	if len(m.logs) > 300 {
		m.logs = m.logs[len(m.logs)-300:]
	}
	m.mu.Unlock()
}

func (m *LinkerManager) AddAccounts(parsed []*AccountJob, ownerUser string) int {
	if ownerUser == "" {
		ownerUser = "mina"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	added := 0
	for _, acc := range parsed {
		acc.OwnerUser = ownerUser
		found := false
		for _, ex := range m.jobs {
			if strings.EqualFold(ex.Email, acc.Email) {
				ex.Password = acc.Password
				ex.OwnerUser = ownerUser
				if acc.Phone != "" {
					ex.Phone = acc.Phone
				}
				if acc.OTPUrl != "" {
					ex.OTPUrl = acc.OTPUrl
				}
				if !strings.Contains(ex.Status, "LINKED") {
					ex.Status = "Pending"
					ex.StatusHex = "#e6edf3"
				}
				found = true
				break
			}
		}
		if !found {
			acc.ID = len(m.jobs) + 1
			m.jobs = append(m.jobs, acc)
			added++
		}
	}
	return added
}

func (m *LinkerManager) StartBatch(maxThreads int, smsTimeoutSec int, baseURL string, callerUser string, isAdmin bool) int {
	m.mu.Lock()
	var pending []*AccountJob
	for _, j := range m.jobs {
		if !strings.Contains(j.Status, "LINKED") {
			if isAdmin || strings.EqualFold(j.OwnerUser, callerUser) {
				pending = append(pending, j)
			}
		}
	}
	m.mu.Unlock()
	if len(pending) == 0 {
		return 0
	}
	if maxThreads <= 0 {
		maxThreads = 50
	}
	if maxThreads > 5000 {
		maxThreads = 5000
	}
	if smsTimeoutSec < 15 {
		smsTimeoutSec = 45
	}

	m.stopFlag.Store(false)
	m.running.Store(true)
	m.AppendLog(fmt.Sprintf("[*] Launching %d account(s) across up to %d concurrent Go Goroutines...", len(pending), maxThreads))

	go func() {
		sem := make(chan struct{}, maxThreads)
		var wg sync.WaitGroup
		for _, job := range pending {
			if m.stopFlag.Load() {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			m.activeGorouts.Add(1)
			go func(j *AccountJob) {
				defer wg.Done()
				defer func() {
					<-sem
					m.activeGorouts.Add(-1)
				}()
				m.processSingleAccount(j, smsTimeoutSec, baseURL)
			}(job)
		}
		wg.Wait()
		m.running.Store(false)
		m.AppendLog("[+] All Go Goroutines finished.")
	}()

	return len(pending)
}

func (m *LinkerManager) updateJob(j *AccountJob, status, colorHex string) {
	m.mu.Lock()
	j.Status = status
	j.StatusHex = colorHex
	m.mu.Unlock()
}

func (m *LinkerManager) processSingleAccount(j *AccountJob, smsTimeoutSec int, baseURL string) {
	email := strings.TrimSpace(j.Email)
	password := strings.TrimSpace(j.Password)
	otpURL := strings.TrimSpace(j.OTPUrl)
	manualCode := strings.TrimSpace(j.ManualCode)
	ownerUser := strings.TrimSpace(j.OwnerUser)
	if ownerUser == "" {
		ownerUser = "mina"
	}

	if !m.store.HasCredits(ownerUser) {
		m.updateJob(j, "❌ No Credits Left", "#f85149")
		m.AppendLog(fmt.Sprintf("[%s] User '%s' has 0 credits remaining.", email, ownerUser))
		return
	}

	sessClient := newInsecureHTTPClient(15 * time.Second)
	seenCodes := make(map[string]bool)
	fallbackCode := ""

	if manualCode == "" && otpURL != "" {
		if req, err := http.NewRequest("GET", otpURL, nil); err == nil {
			req.Header.Set("User-Agent", "curl/8.0")
			if resp, err := sessClient.Do(req); err == nil {
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				preList := extractCodesFromSMSText(string(b))
				for _, c := range preList {
					seenCodes[c] = true
				}
				if len(preList) > 0 {
					fallbackCode = preList[len(preList)-1]
				}
			}
		}
	}

	m.updateJob(j, "Provisioning Mac...", "#58a6ff")
	dev, err := m.pool.GetOrProvisionMac()
	if err != nil {
		m.updateJob(j, "❌ Provision Error", "#f85149")
		m.AppendLog(fmt.Sprintf("[%s] Provisioning error: %v", email, err))
		return
	}

	if m.stopFlag.Load() {
		return
	}

	m.updateJob(j, "SRP Sign-In...", "#58a6ff")
	rComp, spdDict, cpd := runSRPLogin(m.pool, sessClient, email, password, dev, "iTunes")
	var cStatus map[string]interface{}
	if rComp != nil {
		cStatus, _ = rComp["Status"].(map[string]interface{})
	}
	ec := toInt64(cStatus["ec"])
	em := fmt.Sprintf("%v", cStatus["em"])
	hsc := toInt64(cStatus["hsc"])
	au := fmt.Sprintf("%v", cStatus["au"])

	if spdDict == nil && ec != 0 {
		m.updateJob(j, fmt.Sprintf("❌ Auth Error (%d)", ec), "#f85149")
		m.AppendLog(fmt.Sprintf("[%s] Login failed: ec=%d em=%s", email, ec, em))
		return
	}

	needs2FA := (spdDict != nil && toInt64(spdDict["status-code"]) == 409) ||
		hsc == 409 ||
		au == "trustedDeviceSecondaryAuth" ||
		au == "secondaryAuth"

	if needs2FA && spdDict != nil {
		codeToUse := manualCode
		usedSMS := (au == "secondaryAuth")
		valOK := false

		if codeToUse == "" && otpURL != "" {
			m.updateJob(j, "Sending 2FA SMS...", "#d29922")
			_ = triggerSMS2FA(m.pool, sessClient, spdDict, dev, cpd, 1, false)
			usedSMS = true

			if dev.SMSError != "" && fallbackCode == "" {
				m.updateJob(j, "❌ Phone Rate-Limited", "#f85149")
				m.AppendLog(fmt.Sprintf("[%s] %s", email, dev.SMSError))
				return
			}

			maxPolls := smsTimeoutSec * 2 / 3
			if maxPolls < 6 {
				maxPolls = 6
			}
			triedFallback := false
			for pIdx := 1; pIdx <= maxPolls; pIdx++ {
				if m.stopFlag.Load() {
					return
				}
				remS := int(float64(maxPolls-pIdx+1) * 1.5)
				m.updateJob(j, fmt.Sprintf("⏳ Waiting SMS (%ds)...", remS), "#d29922")

				if req, err := http.NewRequest("GET", otpURL, nil); err == nil {
					req.Header.Set("User-Agent", "curl/8.0")
					if resp, err := sessClient.Do(req); err == nil {
						b, _ := io.ReadAll(resp.Body)
						resp.Body.Close()
						codes := extractCodesFromSMSText(string(b))
						for idx := len(codes) - 1; idx >= 0; idx-- {
							c := codes[idx]
							if !seenCodes[c] {
								codeToUse = c
								break
							}
						}
						if codeToUse != "" {
							m.AppendLog(fmt.Sprintf("[%s] Received fresh SMS OTP: %s", email, codeToUse))
							break
						}
					}
				}

				if pIdx == 5 && fallbackCode != "" && !triedFallback {
					triedFallback = true
					m.updateJob(j, fmt.Sprintf("Testing %s...", fallbackCode), "#58a6ff")
					if validate2FACode(m.pool, sessClient, fallbackCode, spdDict, dev, cpd, usedSMS, 1) {
						codeToUse = fallbackCode
						valOK = true
						m.AppendLog(fmt.Sprintf("[%s] Existing SMS code %s accepted!", email, fallbackCode))
						break
					} else if dev.SMSError != "" {
						m.updateJob(j, "❌ Phone Rate-Limited", "#f85149")
						m.AppendLog(fmt.Sprintf("[%s] %s", email, dev.SMSError))
						return
					}
				}

				if pIdx == 10 && dev.SMSError == "" {
					_ = triggerSMS2FA(m.pool, sessClient, spdDict, dev, cpd, 1, true)
					if dev.SMSError != "" {
						m.updateJob(j, "❌ Phone Rate-Limited", "#f85149")
						m.AppendLog(fmt.Sprintf("[%s] %s", email, dev.SMSError))
						return
					}
				}

				time.Sleep(1500 * time.Millisecond)
			}
		}

		if codeToUse == "" {
			m.updateJob(j, "❌ No SMS OTP", "#f85149")
			m.AppendLog(fmt.Sprintf("[%s] Timed out waiting for 6-digit SMS code.", email))
			return
		}

		m.mu.Lock()
		j.SMSCode = codeToUse
		m.mu.Unlock()

		if !valOK {
			m.updateJob(j, fmt.Sprintf("Validating %s...", codeToUse), "#58a6ff")
			valOK = validate2FACode(m.pool, sessClient, codeToUse, spdDict, dev, cpd, usedSMS, 1)
		}

		if valOK {
			m.updateJob(j, "Enrolling MacBook Pro...", "#58a6ff")
			dev.UDID = newUUIDv4Upper()
			rComp2, spdDict2, _ := runSRPLogin(m.pool, sessClient, email, password, dev, "iCloud")
			if spdDict2 != nil {
				var cStat2 map[string]interface{}
				if rComp2 != nil {
					cStat2, _ = rComp2["Status"].(map[string]interface{})
				}
				hsc2 := toInt64(cStat2["hsc"])
				if toInt64(spdDict2["status-code"]) == 409 || hsc2 == 409 {
					rComp3, spdDict3, _ := runSRPLogin(m.pool, sessClient, email, password+codeToUse, dev, "iCloud")
					if spdDict3 != nil {
						spdDict2 = spdDict3
						if rComp3 != nil {
							cStat2, _ = rComp3["Status"].(map[string]interface{})
						}
					}
				}
				spdDict = spdDict2
				hsc = toInt64(cStat2["hsc"])
				if toInt64(spdDict2["status-code"]) != 409 && hsc != 409 {
					needs2FA = false
				}
			}
		} else {
			m.updateJob(j, "❌ 2FA Rejected", "#f85149")
			m.AppendLog(fmt.Sprintf("[%s] 2FA code %s rejected by Apple.", email, codeToUse))
			return
		}
	}

	if needs2FA {
		m.updateJob(j, "❌ Still 409", "#f85149")
		return
	}

	m.updateJob(j, "Adding to Devices List...", "#58a6ff")
	spdDict = registerTrustedDevicePostdata(m.pool, sessClient, email, password, spdDict, dev)

	codeInfo, err := m.pool.GenerateOTPCode(dev.PbB64, dev.HostUUID)
	if err != nil {
		codeInfo = &OTPCodeResult{Code: "------", RemainingSeconds: 30}
	}

	adsid := getStringField(spdDict, "adsid")
	if adsid == "" {
		adsid = getStringField(spdDict, "DsPrsId")
	}
	totpSec := ""
	if skBytes, ok := spdDict["sk"].([]byte); ok {
		totpSec = hex.EncodeToString(skBytes)
	}

	rec, err := m.store.BindDevice(map[string]interface{}{
		"email":           strings.ToLower(email),
		"password":        password,
		"phone":           j.Phone,
		"adsid":           adsid,
		"totp_secret":     totpSec,
		"spd_json":        "{}",
		"adi_pb_b64":      dev.PbB64,
		"host_uuid":       dev.HostUUID,
		"udid":            dev.UDID,
		"mid":             dev.MDM,
		"routing_data":    dev.RoutingData,
		"local_user_uuid": dev.LocalUserUUID,
		"serial_number":   dev.SerialNumber,
		"client_info":     dev.ClientInfo,
		"server_model":    dev.Model,
		"owner_user":      ownerUser,
	})
	if err != nil {
		m.updateJob(j, "❌ DB Save Error", "#f85149")
		return
	}
	m.store.DeductCredit(ownerUser)

	getCodeURL := fmt.Sprintf("%s/getcode/%s", strings.TrimRight(baseURL, "/"), rec.TokenKey)
	m.mu.Lock()
	j.Status = "✅ LINKED (MacBook Pro)"
	j.StatusHex = "#3fb950"
	j.LiveCode = fmt.Sprintf("%s (%ds)", codeInfo.Code, codeInfo.RemainingSeconds)
	j.GetCodeURL = getCodeURL
	j.TokenKey = rec.TokenKey
	j.PbB64 = dev.PbB64
	j.HostUUID = dev.HostUUID
	m.mu.Unlock()

	line := fmt.Sprintf("%s,%s,%s,%s\n", strings.ToLower(email), password, j.Phone, getCodeURL)
	m.savedFileMutex.Lock()
	if f, err := os.OpenFile(m.savedFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		_, _ = f.WriteString(line)
		_ = f.Close()
	}
	m.savedFileMutex.Unlock()

	m.AppendLog(fmt.Sprintf("[+] LINKED %s -> %s (Live Code: %s)", email, getCodeURL, codeInfo.Code))
}

func getStringField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func toInt64(v interface{}) int64 {
	switch tv := v.(type) {
	case int64:
		return tv
	case int:
		return int64(tv)
	case float64:
		return int64(tv)
	default:
		return 0
	}
}
