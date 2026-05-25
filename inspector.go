package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed inspector_ui.html
var inspectorHTML string

const maxCapturedRequests = 500

// CapturedRequest holds metadata about a single proxied HTTP request.
type CapturedRequest struct {
	ID          int         `json:"id"`
	Timestamp   time.Time   `json:"ts"`
	Method      string      `json:"method"`
	Path        string      `json:"path"`
	Host        string      `json:"host"`
	StatusCode  int         `json:"status"`
	DurationMs  int64       `json:"duration_ms"`
	ReqHeaders  http.Header `json:"req_headers,omitempty"`
	RespHeaders http.Header `json:"resp_headers,omitempty"`
	ReqSize     int64       `json:"req_size"`
	RespSize    int64       `json:"resp_size"`
	ReqBody     []byte      `json:"req_body,omitempty"`
}

// Inspector provides a web UI for live inspection of tunnel traffic.
type Inspector struct {
	mu       sync.RWMutex
	requests []CapturedRequest
	nextID   int

	subsMu sync.Mutex
	subs   []chan CapturedRequest

	ServerAddr  string
	TargetAddr  string
	StartTime   time.Time
	Token       string
	ActiveConns *atomic.Int64
}

// NewInspector creates a new request inspector.
func NewInspector(serverAddr, targetAddr, token string, activeConns *atomic.Int64) *Inspector {
	return &Inspector{
		requests:    make([]CapturedRequest, 0, maxCapturedRequests),
		ServerAddr:  serverAddr,
		TargetAddr:  targetAddr,
		StartTime:   time.Now(),
		Token:       token,
		ActiveConns: activeConns,
	}
}

// Record stores a completed request and notifies all SSE subscribers.
func (ins *Inspector) Record(method, path, host string, statusCode int, dur time.Duration, reqHeaders, respHeaders http.Header, reqSize, respSize int64, reqBody []byte) {
	ins.mu.Lock()
	ins.nextID++
	cr := CapturedRequest{
		ID:          ins.nextID,
		Timestamp:   time.Now(),
		Method:      method,
		Path:        path,
		Host:        host,
		StatusCode:  statusCode,
		DurationMs:  dur.Milliseconds(),
		ReqHeaders:  cloneHeaders(reqHeaders),
		RespHeaders: cloneHeaders(respHeaders),
		ReqSize:     reqSize,
		RespSize:    respSize,
		ReqBody:     reqBody,
	}
	if len(ins.requests) >= maxCapturedRequests {
		ins.requests = ins.requests[1:]
	}
	ins.requests = append(ins.requests, cr)
	ins.mu.Unlock()

	ins.subsMu.Lock()
	for _, ch := range ins.subs {
		select {
		case ch <- cr:
		default:
		}
	}
	ins.subsMu.Unlock()
}

func cloneHeaders(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	return h.Clone()
}

func (ins *Inspector) subscribe() (chan CapturedRequest, func()) {
	ch := make(chan CapturedRequest, 64)
	ins.subsMu.Lock()
	ins.subs = append(ins.subs, ch)
	ins.subsMu.Unlock()
	return ch, func() {
		ins.subsMu.Lock()
		for i, s := range ins.subs {
			if s == ch {
				ins.subs = append(ins.subs[:i], ins.subs[i+1:]...)
				break
			}
		}
		ins.subsMu.Unlock()
	}
}

// ServeHTTP routes inspector requests.
func (ins *Inspector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, inspectorHTML)
	case "/api/requests":
		ins.mu.RLock()
		data := make([]CapturedRequest, len(ins.requests))
		copy(data, ins.requests)
		ins.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	case "/api/status":
		ins.mu.RLock()
		total := ins.nextID
		ins.mu.RUnlock()
		var active int64
		if ins.ActiveConns != nil {
			active = ins.ActiveConns.Load()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"server":       ins.ServerAddr,
			"target":       ins.TargetAddr,
			"uptime_sec":   int(time.Since(ins.StartTime).Seconds()),
			"total":        total,
			"token":        ins.Token,
			"active_conns": active,
		})
	case "/api/requests/stream":
		ins.handleSSE(w, r)
	case "/api/replay":
		ins.handleReplay(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (ins *Inspector) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	ch, unsub := ins.subscribe()
	defer unsub()

	for {
		select {
		case cr := <-ch:
			data, _ := json.Marshal(cr)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (ins *Inspector) handleReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ins.mu.RLock()
	var targetReq *CapturedRequest
	for _, cr := range ins.requests {
		if cr.ID == req.ID {
			targetReq = &cr
			break
		}
	}
	ins.mu.RUnlock()

	if targetReq == nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	port := ins.ServerAddr
	if strings.HasPrefix(port, ":") {
		port = "localhost" + port
	}

	newReq, err := http.NewRequest(targetReq.Method, "http://"+port+targetReq.Path, bytes.NewReader(targetReq.ReqBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newReq.Host = targetReq.Host
	for k, vv := range targetReq.ReqHeaders {
		for _, v := range vv {
			newReq.Header.Add(k, v)
		}
	}

	go func() {
		client := &http.Client{Timeout: 30 * time.Second}
		client.Do(newReq)
	}()

	w.WriteHeader(http.StatusOK)
}
