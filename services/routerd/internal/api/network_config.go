package api

import (
	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/routerd/internal/networkcfg"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"runtime"
	"strconv"
)

func registerNetworkConfig(mux *http.ServeMux, store *networkcfg.Store) {
	canSave := func(r *http.Request) bool {
		identity := controlplane.IdentityFromContext(r.Context())
		return store != nil && identity.Enabled && identity.Role == "admin"
	}
	controlplane.Handle(mux, "GET /api/v1/network/configuration", func(w http.ResponseWriter, r *http.Request) {
		state := networkcfg.Empty()
		if store != nil {
			state = store.Read()
		}
		w.Header().Set("ETag", `"`+strconv.FormatUint(state.Revision, 10)+`"`)
		apiresp.JSON(w, r, 200, map[string]any{"snapshot": state, "capabilities": map[string]any{"platform": runtime.GOOS, "can_observe": true, "can_preflight": true, "can_validate_native": true, "can_preview": true, "can_save": canSave(r), "can_apply": false, "store_enabled": store != nil, "preview_backends": []string{"netplan", "networkmanager", "openwrt"}}})
	})
	controlplane.Handle(mux, "POST /api/v1/network/configuration/preview", func(w http.ResponseWriter, r *http.Request) {
		var c networkcfg.Config
		if !readNetworkBody(w, r, &c) {
			return
		}
		preview, err := networkcfg.Compile(c)
		if err != nil {
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, err.Error())
			return
		}
		apiresp.JSON(w, r, 200, preview)
	})
	controlplane.Handle(mux, "PUT /api/v1/network/configuration", func(w http.ResponseWriter, r *http.Request) {
		if !canSave(r) {
			apiresp.Err(w, r, 403, apiresp.CodeUnauthorized, "需要管理员认证并启用网络配置存储")
			return
		}
		var revision uint64
		match := r.Header.Values("If-Match")
		if len(match) != 1 || len(match[0]) < 3 || match[0][0] != '"' || match[0][len(match[0])-1] != '"' {
			apiresp.Err(w, r, 428, apiresp.CodeBadRequest, "需要读取配置版本并提交If-Match")
			return
		}
		revision, err := strconv.ParseUint(match[0][1:len(match[0])-1], 10, 64)
		if err != nil {
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, "配置版本无效")
			return
		}
		var c networkcfg.Config
		if !readNetworkBody(w, r, &c) {
			return
		}
		if err = networkcfg.Validate(c); err != nil {
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, err.Error())
			return
		}
		state, err := store.Save(revision, c)
		if errors.Is(err, networkcfg.ErrConflict) {
			apiresp.Err(w, r, 412, apiresp.CodeBadRequest, err.Error())
			return
		}
		if err != nil {
			apiresp.Err(w, r, 500, apiresp.CodeInternal, "配置保存结果待核实，请重新读取版本后核对")
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatUint(state.Revision, 10)+`"`)
		apiresp.JSON(w, r, 200, state)
	})
}
func readNetworkBody(w http.ResponseWriter, r *http.Request, target any) bool {
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		apiresp.Err(w, r, 415, apiresp.CodeBadRequest, "需要application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 131072)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		apiresp.Err(w, r, 400, apiresp.CodeBadRequest, "配置JSON无效、包含未知字段或超过128KiB")
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		apiresp.Err(w, r, 400, apiresp.CodeBadRequest, "只允许一个JSON配置对象")
		return false
	}
	return true
}
