package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type VirtualMacDevice struct {
	UDID          string `json:"udid"`
	HostUUID      string `json:"host_uuid"`
	SerialNumber  string `json:"serial_number"`
	LocalUserUUID string `json:"local_user_uuid"`
	RoutingData   string `json:"routing_data"`
	Model         string `json:"model"`
	ClientInfo    string `json:"client_info"`
	UserAgent     string `json:"user_agent"`
	PbB64         string `json:"pb_b64"`
	PbLen         int    `json:"pb_len"`
	MDM           string `json:"X-Apple-I-MD-M"`
	MD            string `json:"X-Apple-I-MD"`
	PEToken       string `json:"pe_token,omitempty"`
	SMSError      string `json:"sms_error,omitempty"`
}

type OTPCodeResult struct {
	Code             string `json:"code"`
	RemainingSeconds int    `json:"remaining_seconds"`
	Period           int    `json:"period"`
	Counter          int64  `json:"counter"`
	Algorithm        string `json:"algorithm"`
}

type adiSubprocess struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	reqSeq uint64
}

func newAdiSubprocess(pythonExe, workerScript, workDir string) (*adiSubprocess, error) {
	cmd := exec.Command(pythonExe, "-u", workerScript)
	cmd.Dir = workDir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(stdout, 1024*1024)
	line, err := reader.ReadString('\n')
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("worker startup failed: %v", err)
	}
	if !strings.Contains(line, `"ready"`) {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("unexpected worker greeting: %s", line)
	}
	return &adiSubprocess{
		cmd:    cmd,
		stdin:  stdin,
		reader: reader,
	}, nil
}

func (w *adiSubprocess) call(payload map[string]interface{}) (json.RawMessage, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	id := atomic.AddUint64(&w.reqSeq, 1)
	payload["id"] = id
	rawReq, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	rawReq = append(rawReq, '\n')
	if _, err := w.stdin.Write(rawReq); err != nil {
		return nil, err
	}
	respLine, err := w.reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var envelope struct {
		OK    bool            `json:"ok"`
		ID    uint64          `json:"id"`
		Data  json.RawMessage `json:"data"`
		Error string          `json:"error"`
	}
	if err := json.Unmarshal(respLine, &envelope); err != nil {
		return nil, err
	}
	if !envelope.OK {
		return nil, errors.New(envelope.Error)
	}
	return envelope.Data, nil
}

type AdiEnginePool struct {
	workers    []*adiSubprocess
	rrIdx      uint64
	otpCache   sync.Map // key: string -> OTPCodeResult
	macPool    chan *VirtualMacDevice
	pythonExe  string
	scriptPath string
	workDir    string
}

func NewAdiEnginePool(pythonExe, scriptPath, workDir string, numWorkers int, prewarmPoolSize int) (*AdiEnginePool, error) {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
		if numWorkers > 6 {
			numWorkers = 6
		}
		if numWorkers < 2 {
			numWorkers = 2
		}
	}
	pool := &AdiEnginePool{
		workers:    make([]*adiSubprocess, 0, numWorkers),
		macPool:    make(chan *VirtualMacDevice, prewarmPoolSize),
		pythonExe:  pythonExe,
		scriptPath: scriptPath,
		workDir:    workDir,
	}
	for i := 0; i < numWorkers; i++ {
		w, err := newAdiSubprocess(pythonExe, scriptPath, workDir)
		if err != nil {
			if i == 0 {
				return nil, err
			}
			break
		}
		pool.workers = append(pool.workers, w)
	}

	// Background pre-warmer keeps fresh virtual MacBook Pros ready in RAM
	if prewarmPoolSize > 0 {
		go pool.prewarmLoop()
	}
	return pool, nil
}

func (p *AdiEnginePool) pickWorker() *adiSubprocess {
	idx := atomic.AddUint64(&p.rrIdx, 1)
	return p.workers[int(idx)%len(p.workers)]
}

func (p *AdiEnginePool) prewarmLoop() {
	for {
		if len(p.macPool) < cap(p.macPool) {
			dev, err := p.ProvisionDirect()
			if err == nil && dev != nil {
				select {
				case p.macPool <- dev:
				default:
				}
				continue
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func (p *AdiEnginePool) GetOrProvisionMac() (*VirtualMacDevice, error) {
	select {
	case dev := <-p.macPool:
		return dev, nil
	default:
		return p.ProvisionDirect()
	}
}

func (p *AdiEnginePool) ProvisionDirect() (*VirtualMacDevice, error) {
	raw, err := p.pickWorker().call(map[string]interface{}{
		"cmd": "provision",
	})
	if err != nil {
		return nil, err
	}
	var dev VirtualMacDevice
	var rawMap map[string]interface{}
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return nil, err
	}
	dev.UDID = fmt.Sprintf("%v", rawMap["udid"])
	dev.HostUUID = fmt.Sprintf("%v", rawMap["host_uuid"])
	dev.SerialNumber = fmt.Sprintf("%v", rawMap["serial_number"])
	dev.LocalUserUUID = fmt.Sprintf("%v", rawMap["local_user_uuid"])
	dev.RoutingData = fmt.Sprintf("%v", rawMap["routing_data"])
	dev.Model = fmt.Sprintf("%v", rawMap["model"])
	dev.ClientInfo = fmt.Sprintf("%v", rawMap["client_info"])
	dev.UserAgent = fmt.Sprintf("%v", rawMap["user_agent"])
	dev.PbB64 = fmt.Sprintf("%v", rawMap["pb_b64"])
	dev.MDM = fmt.Sprintf("%v", rawMap["X-Apple-I-MD-M"])
	dev.MD = fmt.Sprintf("%v", rawMap["X-Apple-I-MD"])
	return &dev, nil
}

func (p *AdiEnginePool) RefreshAnisette(dev *VirtualMacDevice) error {
	raw, err := p.pickWorker().call(map[string]interface{}{
		"cmd":           "anisette",
		"pb_b64":        dev.PbB64,
		"host_uuid":     dev.HostUUID,
		"udid":          dev.UDID,
		"local_uuid":    dev.LocalUserUUID,
		"serial_number": dev.SerialNumber,
		"rinfo":         dev.RoutingData,
	})
	if err != nil {
		return err
	}
	var ani map[string]string
	if err := json.Unmarshal(raw, &ani); err != nil {
		return err
	}
	if ani["X-Apple-I-MD-M"] != "" {
		dev.MDM = ani["X-Apple-I-MD-M"]
	}
	if ani["X-Apple-I-MD"] != "" {
		dev.MD = ani["X-Apple-I-MD"]
	}
	return nil
}

func (p *AdiEnginePool) SyncMachine(dev *VirtualMacDevice, simB64 string) error {
	raw, err := p.pickWorker().call(map[string]interface{}{
		"cmd":           "sync",
		"pb_b64":        dev.PbB64,
		"host_uuid":     dev.HostUUID,
		"sim_b64":       simB64,
		"udid":          dev.UDID,
		"local_uuid":    dev.LocalUserUUID,
		"serial_number": dev.SerialNumber,
		"rinfo":         dev.RoutingData,
	})
	if err != nil {
		return err
	}
	var res map[string]string
	if err := json.Unmarshal(raw, &res); err != nil {
		return err
	}
	if res["pb_b64"] != "" {
		dev.PbB64 = res["pb_b64"]
	}
	if res["X-Apple-I-MD-M"] != "" {
		dev.MDM = res["X-Apple-I-MD-M"]
	}
	if res["X-Apple-I-MD"] != "" {
		dev.MD = res["X-Apple-I-MD"]
	}
	return nil
}

func (p *AdiEnginePool) GenerateOTPCode(pbB64, hostUUID string) (*OTPCodeResult, error) {
	now := time.Now().Unix()
	counter := now / 30
	rem := int(30 - (now % 30))
	tail := pbB64
	if len(tail) > 48 {
		tail = tail[len(tail)-48:]
	}
	cacheKey := fmt.Sprintf("%s|%s|%d", tail, strings.ToLower(strings.TrimSpace(hostUUID)), counter)
	if cached, ok := p.otpCache.Load(cacheKey); ok {
		c := cached.(OTPCodeResult)
		c.RemainingSeconds = rem
		return &c, nil
	}

	raw, err := p.pickWorker().call(map[string]interface{}{
		"cmd":       "otp_code",
		"pb_b64":    pbB64,
		"host_uuid": hostUUID,
		"timestamp": float64(now),
	})
	if err != nil {
		return nil, err
	}
	var out OTPCodeResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	out.RemainingSeconds = rem
	p.otpCache.Store(cacheKey, out)
	return &out, nil
}

func (p *AdiEnginePool) DBLoadAll(dbPath string) ([]map[string]interface{}, error) {
	raw, err := p.pickWorker().call(map[string]interface{}{
		"cmd":     "db_load_all",
		"db_path": dbPath,
	})
	if err != nil {
		return nil, err
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (p *AdiEnginePool) DBBind(dbPath string, payload map[string]interface{}) (map[string]interface{}, error) {
	raw, err := p.pickWorker().call(map[string]interface{}{
		"cmd":     "db_bind",
		"db_path": dbPath,
		"payload": payload,
	})
	if err != nil {
		return nil, err
	}
	var res map[string]interface{}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (p *AdiEnginePool) DBUsersLoad(dbPath string) ([]map[string]interface{}, error) {
	raw, err := p.pickWorker().call(map[string]interface{}{
		"cmd":     "db_users_load",
		"db_path": dbPath,
	})
	if err != nil {
		return nil, err
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (p *AdiEnginePool) DBUserUpsert(dbPath string, user map[string]interface{}) error {
	_, err := p.pickWorker().call(map[string]interface{}{
		"cmd":     "db_user_upsert",
		"db_path": dbPath,
		"user":    user,
	})
	return err
}

func (p *AdiEnginePool) DBUserDelete(dbPath string, username string) error {
	_, err := p.pickWorker().call(map[string]interface{}{
		"cmd":      "db_user_delete",
		"db_path":  dbPath,
		"username": username,
	})
	return err
}
