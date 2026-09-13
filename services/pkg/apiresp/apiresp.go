// Package apiresp 提供 cythsec 各 Go 服务的统一 HTTP 响应封装与业务码。
//
// 设计目标：消除 routerd / policyd / dnsd / telemetryd 之间重复实现 envelope 与
// 响应工具函数。未来新增 Go 服务直接 import 本包即可获得一致的响应格式。
//
// 统一响应体（JSON）：
//
//	{ "code": <int>, "data": <any>, "error": <string>, "request_id": <string> }
//
// 其中 code 为业务码（见下方 Code* 常量），data 为成功负载，error 为错误描述，
// request_id 为请求追踪 ID（由调用方通过请求上下文传入，便于链路排查）。
// 旧客户端若只读取 data 字段，本结构保持向后兼容不受影响。
package apiresp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
)

// 业务码（code 字段）语义约定：
//
//	1xxx = 成功类
//	4xxx = 客户端错误（参数 / 鉴权 / 方法等）
//	5xxx = 服务端内部错误
const (
	CodeOK               = 1000 // 成功
	CodeBadRequest       = 4001 // 参数错误：请求体 / 查询参数非法
	CodeUnauthorized     = 4003 // 未认证 / 无权限
	CodeNotFound         = 4004 // 资源不存在
	CodeMethodNotAllowed = 4005 // 方法不允许（如 POST 到只读 GET 接口）
	CodeInternal         = 5001 // 内部错误：服务端处理异常
)

// ctxKey 是请求上下文里存放 request_id 的键类型。
type ctxKey struct{}

// WithRequestID 把请求追踪 ID 放入上下文，供响应写入 envelope 与日志复用。
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// RequestIDFromContext 从上下文取出请求追踪 ID（缺省返回空串）。
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey{}).(string); ok {
		return v
	}
	return ""
}

// NewRequestID 生成一个新的请求追踪 ID（16 字节随机，十六进制编码）。
func NewRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// 极不可能失败；失败时退化为伪随机十六进制。
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b)
}

// Envelope 是统一的 JSON 响应体。
type Envelope struct {
	Code      int    `json:"code"`                 // 业务码，1000 表示成功
	Data      any    `json:"data,omitempty"`       // 成功时的业务负载（失败时为 null）
	Error     string `json:"error,omitempty"`      // 错误描述，仅失败时存在
	RequestID string `json:"request_id,omitempty"` // 请求追踪 ID
}

// JSON 写成功响应（code=1000），自动从请求上下文注入 request_id。
// 若 r 为 nil，则不写入 request_id。
func JSON(w http.ResponseWriter, r *http.Request, status int, data any) {
	rid := ""
	if r != nil {
		rid = RequestIDFromContext(r.Context())
	}
	write(w, status, Envelope{Code: CodeOK, Data: data, RequestID: rid})
}

// Err 写错误响应，code 为业务码，msg 为错误描述。
// 若 r 非 nil，则从请求上下文注入 request_id。
func Err(w http.ResponseWriter, r *http.Request, status, code int, msg string) {
	rid := ""
	if r != nil {
		rid = RequestIDFromContext(r.Context())
	}
	write(w, status, Envelope{Code: code, Error: msg, RequestID: rid})
}

// write 统一编码并写出 envelope。
func write(w http.ResponseWriter, status int, env Envelope) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(env); err != nil {
		log.Printf("apiresp: 写响应失败: %v", err)
	}
}
