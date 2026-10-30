package api

import (
	"context"
	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/routerd/internal/networkcfg"
	"errors"
	"net/http"
)

func registerNetworkValidation(mux *http.ServeMux, validate func(context.Context, networkcfg.Config) (networkcfg.NativeValidation, error)) {
	controlplane.Handle(mux, "POST /api/v1/network/configuration/native-validation", func(w http.ResponseWriter, r *http.Request) {
		var c networkcfg.Config
		if !readNetworkBody(w, r, &c) {
			return
		}
		if err := networkcfg.Validate(c); err != nil {
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, err.Error())
			return
		}
		result, err := validate(r.Context(), c)
		if errors.Is(err, networkcfg.ErrObservationBusy) {
			w.Header().Set("Retry-After", "1")
			apiresp.Err(w, r, 429, apiresp.CodeBadRequest, "正在校验原生配置，请稍后重试")
			return
		}
		if err != nil {
			apiresp.Err(w, r, 503, apiresp.CodeInternal, "原生配置校验未完成")
			return
		}
		apiresp.JSON(w, r, 200, result)
	})
}
