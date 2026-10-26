package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"cythsec/services/pkg/apiresp"
	"cythsec/services/pkg/httpx"
)

// Access is immutable after startup. Policies contain hashes of high-entropy
// credentials, never passwords. Revocation requires replacing the file and restart.
type Access struct{ entries []accessEntry }
type accessEntry struct {
	name, role string
	digest     [32]byte
}
type AccessIdentity struct {
	Enabled   bool   `json:"enabled"`
	Name      string `json:"name,omitempty"`
	Role      string `json:"role,omitempty"`
	CanIngest bool   `json:"can_ingest"`
}
type identityKey struct{}

var principalName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func LoadAccess(path string) (*Access, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open access policy: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return nil, errors.New("access policy must be a regular private file, at most 64 KiB")
	}
	var config struct {
		Principals []struct {
			Name   string `json:"name"`
			Role   string `json:"role"`
			SHA256 string `json:"sha256"`
		} `json:"principals"`
	}
	decoder := json.NewDecoder(io.LimitReader(f, 65537))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		return nil, errors.New("invalid access policy")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || len(config.Principals) == 0 || len(config.Principals) > 128 {
		return nil, errors.New("invalid access policy entries")
	}
	a := &Access{}
	names, digests := map[string]bool{}, map[string]bool{}
	for _, p := range config.Principals {
		raw, err := hex.DecodeString(p.SHA256)
		if err != nil || len(raw) != 32 || !principalName.MatchString(p.Name) || (p.Role != "viewer" && p.Role != "operator" && p.Role != "admin") || names[p.Name] || digests[string(raw)] {
			return nil, errors.New("invalid or duplicate access principal")
		}
		names[p.Name], digests[string(raw)] = true, true
		var digest [32]byte
		copy(digest[:], raw)
		a.entries = append(a.entries, accessEntry{p.Name, p.Role, digest})
	}
	return a, nil
}
func (a *Access) identity(r *http.Request, service string) (AccessIdentity, bool) {
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return AccessIdentity{}, false
	}
	parts := strings.Split(headers[0], " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) < 32 || len(parts[1]) > 256 {
		return AccessIdentity{}, false
	}
	digest := sha256.Sum256([]byte(parts[1]))
	identity := AccessIdentity{}
	for _, entry := range a.entries {
		if subtle.ConstantTimeCompare(digest[:], entry.digest[:]) == 1 {
			identity = AccessIdentity{true, entry.name, entry.role, service == "telemetryd" && entry.role != "viewer"}
		}
	}
	return identity, identity.Enabled
}
func (a *Access) middleware(service string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if a == nil || ((r.Method == "GET" || r.Method == "HEAD") && r.URL.Path == "/healthz") {
				next.ServeHTTP(w, r)
				return
			}
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if r.TLS == nil && (err != nil || !net.ParseIP(host).IsLoopback()) {
				if holder := httpx.RouteHolderFromContext(r.Context()); holder != nil {
					holder.Set("/transport-required")
				}
				apiresp.Err(w, r, 403, apiresp.CodeUnauthorized, "访问认证需要 TLS 或本机回环代理")
				return
			}
			identity, valid := a.identity(r, service)
			if !valid {
				if holder := httpx.RouteHolderFromContext(r.Context()); holder != nil {
					holder.Set("/unauthenticated")
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="cythsec"`)
				apiresp.Err(w, r, 401, apiresp.CodeUnauthorized, "需要有效的服务访问凭据")
				return
			}
			read := r.Method == "GET" || r.Method == "HEAD"
			ingest := r.Method == "POST" && (r.URL.Path == "/api/v1/analytics/imports" || r.URL.Path == "/api/v1/analytics/ingest") && identity.CanIngest
			if !read && !ingest {
				if holder := httpx.RouteHolderFromContext(r.Context()); holder != nil {
					holder.Set("/forbidden")
				}
				apiresp.Err(w, r, 403, apiresp.CodeUnauthorized, "当前身份无此操作权限")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, identity)))
		})
	}
}
func accessSession(w http.ResponseWriter, r *http.Request) {
	identity, _ := r.Context().Value(identityKey{}).(AccessIdentity)
	apiresp.JSON(w, r, http.StatusOK, identity)
}
