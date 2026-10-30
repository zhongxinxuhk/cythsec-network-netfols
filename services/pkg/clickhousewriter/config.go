package clickhousewriter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DefaultClient keeps the standalone loopback defaults. Deployments override them
// through a private file, environment, then explicit command-line flags.
func DefaultClient() Client {
	return Client{Binary: "clickhouse-client", Host: "127.0.0.1", Port: 9000,
		User: "default", Database: "default", Table: "flow_records_v2", Timeout: 10 * time.Second}
}

type clientFile struct {
	Client       *string `json:"client"`
	Host         *string `json:"host"`
	Port         *int    `json:"port"`
	User         *string `json:"user"`
	Database     *string `json:"database"`
	Table        *string `json:"table"`
	Secure       *bool   `json:"secure"`
	Timeout      *string `json:"timeout"`
	PasswordFile *string `json:"password_file"`
}

type middlewareFile struct {
	Version    int         `json:"version"`
	ClickHouse *clientFile `json:"clickhouse"`
}

// LoadClientConfig resolves file and environment values without modifying the
// process environment. Call Validate after applying explicit CLI overrides.
// Passwords are never accepted as CLI arguments or literal JSON properties.
func LoadClientConfig(path string) (Client, error) { return loadClientConfig(path, os.LookupEnv) }

func loadClientConfig(path string, lookup func(string) (string, bool)) (Client, error) {
	c := DefaultClient()
	passwordFile := ""
	if path != "" {
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return c, errors.New("无法读取中间件配置文件")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return c, errors.New("中间件配置须为不超过1MiB的普通文件")
		}
		var cfg middlewareFile
		data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil || len(data) > 1<<20 {
			return c, errors.New("读取中间件配置失败或超限")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			return c, errors.New("中间件配置格式无效或含未知字段")
		}
		if decoder.Decode(new(any)) != io.EOF || cfg.Version != 1 || cfg.ClickHouse == nil {
			return c, errors.New("中间件配置版本或文件尾部无效")
		}
		for target, value := range map[*string]*string{&c.Binary: cfg.ClickHouse.Client, &c.Host: cfg.ClickHouse.Host, &c.User: cfg.ClickHouse.User, &c.Database: cfg.ClickHouse.Database, &c.Table: cfg.ClickHouse.Table} {
			if value != nil {
				*target = *value
			}
		}
		if cfg.ClickHouse.Port != nil {
			c.Port = *cfg.ClickHouse.Port
		}
		if cfg.ClickHouse.Secure != nil {
			c.Secure = *cfg.ClickHouse.Secure
		}
		if cfg.ClickHouse.Timeout != nil {
			c.Timeout, err = time.ParseDuration(*cfg.ClickHouse.Timeout)
			if err != nil {
				return c, errors.New("clickhouse.timeout 必须是有效时长")
			}
		}
		if cfg.ClickHouse.PasswordFile != nil {
			passwordFile = *cfg.ClickHouse.PasswordFile
			if passwordFile != "" && !filepath.IsAbs(passwordFile) {
				passwordFile = filepath.Join(filepath.Dir(path), passwordFile)
			}
		}
	}
	for name, target := range map[string]*string{"CLICKHOUSE_CLIENT": &c.Binary, "CLICKHOUSE_HOST": &c.Host, "CLICKHOUSE_USER": &c.User, "CLICKHOUSE_DATABASE": &c.Database, "CLICKHOUSE_TABLE": &c.Table} {
		if value, set := lookup(name); set && value != "" {
			*target = value
		}
	}
	if value, set := lookup("CLICKHOUSE_PORT"); set && value != "" {
		port, err := strconv.Atoi(value)
		if err != nil {
			return c, errors.New("CLICKHOUSE_PORT 必须是整数")
		}
		c.Port = port
	}
	if value, set := lookup("CLICKHOUSE_SECURE"); set && value != "" {
		secure, err := strconv.ParseBool(value)
		if err != nil {
			return c, errors.New("CLICKHOUSE_SECURE 必须是布尔值")
		}
		c.Secure = secure
	}
	if value, set := lookup("CLICKHOUSE_TIMEOUT"); set && value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil {
			return c, errors.New("CLICKHOUSE_TIMEOUT 必须是有效时长")
		}
		c.Timeout = timeout
	}
	credential, hasCredential := lookup("CLICKHOUSE_PASSWORD")
	envFile, hasFile := lookup("CLICKHOUSE_PASSWORD_FILE")
	if hasFile && envFile != "" {
		if hasCredential {
			return c, errors.New("CLICKHOUSE_PASSWORD 与 CLICKHOUSE_PASSWORD_FILE 不能同时设置")
		}
		passwordFile = envFile
	}
	if !hasCredential && passwordFile != "" {
		f, err := os.OpenFile(passwordFile, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return c, errors.New("无法读取 ClickHouse 密码文件")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
			return c, errors.New("ClickHouse 密码文件必须是不超过64KiB的普通文件")
		}
		data, err := io.ReadAll(io.LimitReader(f, 65537))
		if err != nil || len(data) > 65536 {
			return c, errors.New("读取 ClickHouse 密码文件失败或超限")
		}
		credential = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	}
	if strings.ContainsRune(credential, '\x00') || len(credential) > 65536 {
		return c, fmt.Errorf("ClickHouse 密码长度或格式无效")
	}
	c.credential = &credential
	return c, nil
}
