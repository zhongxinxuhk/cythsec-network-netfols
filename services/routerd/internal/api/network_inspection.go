package api

import (
	"context"
	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/routerd/internal/networkcfg"
	"errors"
	"net/http"
)

func registerNetworkInspection(mux *http.ServeMux, inspect func(context.Context, string) (networkcfg.PersistentInspection, error)) {
	controlplane.Handle(mux, "POST /api/v1/network/configuration/persistent-inspection", func(w http.ResponseWriter, r *http.Request) {
		var query struct {
			Backend string `json:"backend"`
		}
		if !readNetworkBody(w, r, &query) {
			return
		}
		if !networkcfg.ValidBackend(query.Backend) {
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, "选择受支持的目标管理器")
			return
		}
		result, err := inspect(r.Context(), query.Backend)
		if errors.Is(err, networkcfg.ErrObservationBusy) {
			w.Header().Set("Retry-After", "1")
			apiresp.Err(w, r, 429, apiresp.CodeBadRequest, "正在读取配置来源，请稍后重试")
			return
		}
		if err != nil {
			apiresp.Err(w, r, 503, apiresp.CodeInternal, "持久配置读取未完成")
			return
		}
		apiresp.JSON(w, r, 200, result)
	})
}
