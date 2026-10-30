package api

import (
	"context"
	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/controlplane"
	"cythsec/services/routerd/internal/networkcfg"
	"errors"
	"net/http"
)

func registerNetworkObservation(mux *http.ServeMux, observe func(context.Context) (networkcfg.Observation, error)) {
	capture := func(w http.ResponseWriter, r *http.Request) (networkcfg.Observation, bool) {
		result, err := observe(r.Context())
		if errors.Is(err, networkcfg.ErrObservationBusy) {
			w.Header().Set("Retry-After", "1")
			apiresp.Err(w, r, 429, apiresp.CodeBadRequest, "正在读取网络环境，请稍后重试")
			return result, false
		}
		if err != nil {
			apiresp.Err(w, r, 503, apiresp.CodeInternal, "网络环境读取未完成")
			return result, false
		}
		return result, true
	}
	controlplane.Handle(mux, "GET /api/v1/network/configuration/observation", func(w http.ResponseWriter, r *http.Request) {
		result, ok := capture(w, r)
		if ok {
			apiresp.JSON(w, r, 200, result)
		}
	})
	controlplane.Handle(mux, "POST /api/v1/network/configuration/preflight", func(w http.ResponseWriter, r *http.Request) {
		var c networkcfg.Config
		if !readNetworkBody(w, r, &c) {
			return
		}
		if err := networkcfg.Validate(c); err != nil {
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, err.Error())
			return
		}
		snapshot, ok := capture(w, r)
		if !ok {
			return
		}
		report, err := networkcfg.Compare(c, snapshot)
		if err != nil {
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, err.Error())
			return
		}
		apiresp.JSON(w, r, 200, report)
	})
}
