// Package api 提供 routerd 的 HTTP 控制面 API。
// 供 Web Console 消费：获取系统信息、网卡/IP、路由表等。
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"cythsec/services/routerd/internal/netinfo"
)

// NewServer 构造 HTTP 多路复用器，注册 routerd 的 v1 API。
func NewServer() http.Handler {
	mux := http.NewServeMux()

	// 健康检查
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// v1 控制面 API（供 Web Console 对接）
	mux.HandleFunc("GET /api/v1/system", handleSystem)
	mux.HandleFunc("GET /api/v1/interfaces", handleInterfaces)
	mux.HandleFunc("GET /api/v1/routes", handleRoutes)
	mux.HandleFunc("GET /api/v1/traffic", handleTraffic)

	return logMiddleware(mux)
}

// 统一 JSON 响应包装：{ "data": ... }，预留 future 的 code/error 结构。
type envelope struct {
	Data  any    `json:"data"`
	Error string `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, envelope{Error: msg})
}

func handleSystem(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, envelope{Data: netinfo.GetSystem()})
}

func handleInterfaces(w http.ResponseWriter, _ *http.Request) {
	ifaces, err := netinfo.ListInterfaces()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{Data: ifaces})
}

func handleRoutes(w http.ResponseWriter, _ *http.Request) {
	routes, err := netinfo.ListRoutes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{Data: routes})
}

func handleTraffic(w http.ResponseWriter, _ *http.Request) {
	traf, err := netinfo.ListTraffic()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{Data: traf})
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start))
	})
}
