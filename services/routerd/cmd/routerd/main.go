// routerd - cythsec 路由器核心服务（控制面）。
//
// 首版只提供本机网络信息采集的只读 HTTP API，作为 Web Console 的数据后端：
//
//	GET /healthz          健康检查
//	GET /api/v1/system    系统概貌（hostname / os / arch / go 版本）
//	GET /api/v1/interfaces  网卡、IP、接口状态
//	GET /api/v1/routes    路由表
//	GET /api/v1/traffic   网卡流量计数（rx/tx bytes & packets）
//
// 监听地址可通过 -addr 覆盖，默认 :8080。
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cythsec/services/routerd/internal/api"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address, e.g. :8080 or 127.0.0.1:8080")
	flag.Parse()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.NewServer(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// 优雅退出：收到 SIGINT/SIGTERM 后关闭。
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("shutting down ...")
		_ = srv.Close()
	}()

	log.Printf("routerd listening on %s", *addr)
	log.Printf("  GET /healthz")
	log.Printf("  GET /api/v1/system")
	log.Printf("  GET /api/v1/interfaces")
	log.Printf("  GET /api/v1/routes")
	log.Printf("  GET /api/v1/traffic")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
	log.Println("bye")
}
