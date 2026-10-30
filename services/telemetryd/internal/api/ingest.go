package api

import (
	"cythsec/services/pkg/apiresp"
	"cythsec/services/telemetryd/internal/aggregate"
	"errors"
	"net/http"
)

func ingestStatus(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !aggregateAccess(w, r, opts.Aggregates) {
			return
		}
		if opts.Ingest == nil {
			apiresp.JSON(w, r, 200, aggregate.IngestStatus{State: "disabled"})
			return
		}
		apiresp.JSON(w, r, 200, opts.Ingest.Status())
	}
}
func enqueueAggregate(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !aggregateAccess(w, r, opts.Aggregates) {
			return
		}
		if opts.Ingest == nil {
			apiresp.Err(w, r, 503, apiresp.CodeInternal, "聚合磁盘队列未启用")
			return
		}
		data, ok := readAggregateBody(w, r)
		if !ok {
			return
		}
		item, duplicate, err := opts.Ingest.Enqueue(data)
		switch {
		case errors.Is(err, aggregate.ErrInvalid):
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, "聚合格式、字段或完整性校验失败")
			return
		case errors.Is(err, aggregate.ErrFull):
			w.Header().Set("Retry-After", "1")
			apiresp.Err(w, r, 507, apiresp.CodeInternal, "待写队列已满，请保留输入并稍后重试")
			return
		case err != nil:
			apiresp.Err(w, r, 500, apiresp.CodeInternal, "队列未确认持久化，请保留输入并重试")
			return
		}
		apiresp.JSON(w, r, 202, struct {
			ID        string `json:"id"`
			Duplicate bool   `json:"duplicate"`
			Durable   bool   `json:"durable"`
			Stage     string `json:"acknowledged_stage"`
		}{item.ID, duplicate, true, "queue"})
	}
}
