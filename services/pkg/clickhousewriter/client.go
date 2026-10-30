package clickhousewriter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	Binary, Host, User, Database, Table string
	Port                                int
	Secure                              bool
	Timeout                             time.Duration
	credential                          *string
}

type errorBuffer struct{ bytes.Buffer }

func (b *errorBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if left := 4096 - b.Len(); left > 0 {
		b.Buffer.Write(p[:min(left, len(p))])
	}
	return n, nil
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (c Client) Validate() error {
	if strings.ContainsAny(c.Host, "/@?# \t\r\n\x00") {
		return errors.New("ClickHouse host 只能是主机名或IP，不能包含连接URI或凭据")
	}
	if c.Binary == "" || c.Host == "" || c.User == "" || c.Port <= 0 || c.Port > 65535 || c.Timeout <= 0 || !identifier.MatchString(c.Database) || !identifier.MatchString(c.Table) {
		return errors.New("客户端、主机、端口、用户、超时或库表名无效")
	}
	return nil
}

func (c Client) Target() string {
	return fmt.Sprintf("native://%s@%s:%d/%s/%s?secure=%t", c.User, c.Host, c.Port, c.Database, c.Table, c.Secure)
}

const credentialEnvironment = "CLICKHOUSE_PASSWORD"

func (c Client) Send(ctx context.Context, id string, data []byte) error {
	if err := c.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	args := []string{"--host", c.Host, "--port", strconv.Itoa(c.Port), "--user", c.User,
		"--database", c.Database, "--async_insert=0", "--insert_deduplicate=1", "--insert_deduplication_token", id,
		"--input_format_skip_unknown_fields=0", "--input_format_json_ignore_unknown_keys_in_named_tuple=0",
		"--input_format_json_defaults_for_missing_elements_in_named_tuple=0", "--input_format_null_as_default=0",
		"--query", "INSERT INTO " + c.Table + " FORMAT JSONEachRow"}
	if c.Secure {
		args = append(args, "--secure")
	}
	// ponytail: 每批启动一次官方 native 客户端；需要持续高吞吐时据实测换长连接驱动。
	// 密码通过官方 CLICKHOUSE_PASSWORD 环境变量继承，不进入命令行或队列元数据。
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	credential := os.Getenv(credentialEnvironment)
	if c.credential != nil {
		credential = *c.credential
	}
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, credentialEnvironment+"=") && !strings.HasPrefix(item, credentialEnvironment+"_FILE=") {
			cmd.Env = append(cmd.Env, item)
		}
	}
	cmd.Env = append(cmd.Env, credentialEnvironment+"="+credential)
	cmd.Stdin = bytes.NewReader(data)
	var stderr errorBuffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		text := stderr.String()
		if credential != "" {
			text = "[REDACTED]" // Never expose a truncated credential from bounded stderr.
		}
		if len(text) > 4096 {
			text = text[len(text)-4096:]
		}
		return fmt.Errorf("native 写入失败: %w: %s", err, text)
	}
	return nil
}
