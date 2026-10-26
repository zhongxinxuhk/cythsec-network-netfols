package api

import (
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"

	"cythsec/services/pkg/apiresp"
	"cythsec/services/telemetryd/internal/aggregate"
)

func aggregateAccess(w http.ResponseWriter, r *http.Request, s *aggregate.Store) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		apiresp.Err(w, r, 403, apiresp.CodeUnauthorized, "聚合存储仅接受本机连接")
		return false
	}
	if s == nil {
		apiresp.Err(w, r, 503, apiresp.CodeInternal, "聚合持久化未启用")
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	return true
}
func listImports(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !aggregateAccess(w, r, opts.Aggregates) {
			return
		}
		items := opts.Aggregates.List()
		apiresp.JSON(w, r, 200, struct {
			Items   []aggregate.Import `json:"items"`
			Total   int                `json:"total"`
			Backend string             `json:"backend"`
		}{items, len(items), "local-immutable-jsonl"})
	}
}
func importAggregates(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !aggregateAccess(w, r, opts.Aggregates) {
			return
		}
		data, ok := readAggregateBody(w, r)
		if !ok {
			return
		}
		item, duplicate, err := opts.Aggregates.Put(data)
		switch {
		case errors.Is(err, aggregate.ErrInvalid):
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, "聚合格式、字段或完整性校验失败")
			return
		case errors.Is(err, aggregate.ErrFull):
			apiresp.Err(w, r, 507, apiresp.CodeInternal, "聚合存储容量已满，未写入")
			return
		case err != nil:
			apiresp.Err(w, r, 500, apiresp.CodeInternal, "聚合数据未确认持久化，请检查存储后重试")
			return
		}
		status := http.StatusCreated
		if duplicate {
			status = http.StatusOK
		}
		apiresp.JSON(w, r, status, struct {
			Import    aggregate.Import `json:"import"`
			Duplicate bool             `json:"duplicate"`
			Durable   bool             `json:"durable"`
		}{item, duplicate, true})
	}
}
func queryAggregates(opts ServerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !aggregateAccess(w, r, opts.Aggregates) {
			return
		}
		values := r.URL.Query()
		defaults := map[string]uint64{"from": 0, "to": 1<<53 - 1, "offset": 0, "limit": 100}
		for key, list := range values {
			if _, ok := defaults[key]; !ok || len(list) != 1 {
				apiresp.Err(w, r, 400, apiresp.CodeBadRequest, "查询参数无效")
				return
			}
			n, err := strconv.ParseUint(list[0], 10, 53)
			if err != nil {
				apiresp.Err(w, r, 400, apiresp.CodeBadRequest, "查询参数必须是安全非负整数")
				return
			}
			defaults[key] = n
		}
		if defaults["to"] <= defaults["from"] || defaults["offset"] > 1024 || defaults["limit"] < 1 || defaults["limit"] > 100 {
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, "查询范围或分页参数无效")
			return
		}
		page, err := opts.Aggregates.Query(r.PathValue("id"), defaults["from"], defaults["to"], int(defaults["offset"]), int(defaults["limit"]))
		if errors.Is(err, aggregate.ErrNotFound) {
			apiresp.Err(w, r, 404, apiresp.CodeNotFound, "聚合批次不存在")
			return
		}
		if err != nil {
			apiresp.Err(w, r, 500, apiresp.CodeInternal, "持久化数据读取或校验失败")
			return
		}
		apiresp.JSON(w, r, 200, page)
	}
}

func readAggregateBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-ndjson" {
		apiresp.Err(w, r, 415, apiresp.CodeBadRequest, "请上传聚合 JSONL（application/x-ndjson）")
		return nil, false
	}
	body := http.MaxBytesReader(w, r.Body, aggregate.MaxBatchBytes)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			apiresp.Err(w, r, 413, apiresp.CodeBadRequest, "聚合文件不能超过 1 MiB")
		} else {
			apiresp.Err(w, r, 400, apiresp.CodeBadRequest, "读取聚合文件失败")
		}
		return nil, false
	}

	return data, true
}
