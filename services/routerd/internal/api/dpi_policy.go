package api

import (
	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/routerd/internal/dpipolicy"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
)

// registerDPIPolicy 注册 DPI 策略的读写端点。
//
// 读：任何已认证/本地请求都可读取目录与当前策略（目录含未实现模块的 availability）。
// 写：必须管理员身份且启用了持久化目录；与 network configuration 保持同一套
// If-Match/412/428 语义，避免"两个控制面两套版本规则"。
func registerDPIPolicy(mux *http.ServeMux, store *dpipolicy.Store) {
	canSave := func(r *http.Request) bool {
		identity := controlplane.IdentityFromContext(r.Context())
		return store != nil && identity.Enabled && identity.Role == "admin"
	}
	controlplane.Handle(mux, "GET /api/v1/dpi/modules", func(w http.ResponseWriter, r *http.Request) {
		apiresp.JSON(w, r, http.StatusOK, map[string]any{
			"schema_version": dpipolicy.SchemaVersion,
			"modules":        dpipolicy.Modules,
		})
	})
	controlplane.Handle(mux, "GET /api/v1/dpi/policy", func(w http.ResponseWriter, r *http.Request) {
		state := dpipolicy.Empty()
		if store != nil {
			state = store.Read()
		}
		w.Header().Set("ETag", `"`+strconv.FormatUint(state.Revision, 10)+`"`)
		apiresp.JSON(w, r, http.StatusOK, map[string]any{
			"snapshot": state,
			"capabilities": map[string]any{
				"can_save":      canSave(r),
				"store_enabled": store != nil,
			},
		})
	})
	controlplane.Handle(mux, "PUT /api/v1/dpi/policy", func(w http.ResponseWriter, r *http.Request) {
		if !canSave(r) {
			apiresp.Err(w, r, http.StatusForbidden, apiresp.CodeUnauthorized, "需要管理员认证并启用 DPI 策略存储")
			return
		}
		match := r.Header.Values("If-Match")
		if len(match) != 1 || len(match[0]) < 3 || match[0][0] != '"' || match[0][len(match[0])-1] != '"' {
			apiresp.Err(w, r, http.StatusPreconditionRequired, apiresp.CodeBadRequest, "需要读取策略版本并提交 If-Match")
			return
		}
		revision, err := strconv.ParseUint(match[0][1:len(match[0])-1], 10, 64)
		if err != nil {
			apiresp.Err(w, r, http.StatusBadRequest, apiresp.CodeBadRequest, "策略版本无效")
			return
		}
		var policy dpipolicy.Policy
		if !readDPIPolicyBody(w, r, &policy) {
			return
		}
		state, err := store.Save(revision, policy)
		if errors.Is(err, dpipolicy.ErrConflict) {
			apiresp.Err(w, r, http.StatusPreconditionFailed, apiresp.CodeBadRequest, err.Error())
			return
		}
		if err != nil {
			// Validate 的错误是用户输入问题；其它错误是落盘问题。两者都不能报成成功。
			apiresp.Err(w, r, http.StatusBadRequest, apiresp.CodeBadRequest, err.Error())
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatUint(state.Revision, 10)+`"`)
		apiresp.JSON(w, r, http.StatusOK, state)
	})
}

func readDPIPolicyBody(w http.ResponseWriter, r *http.Request, target *dpipolicy.Policy) bool {
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		apiresp.Err(w, r, http.StatusUnsupportedMediaType, apiresp.CodeBadRequest, "需要 application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 131072)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		apiresp.Err(w, r, http.StatusBadRequest, apiresp.CodeBadRequest, "DPI 策略 JSON 无效、包含未知字段或超过 128KiB")
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		apiresp.Err(w, r, http.StatusBadRequest, apiresp.CodeBadRequest, "只允许一个 JSON 策略对象")
		return false
	}
	return true
}
