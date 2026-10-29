// cythsec-ch-write 将 FlowRecord JSONL 通过持久化批次队列写入 ClickHouse native 连接。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cythsec/services/pkg/clickhousewriter"
	"cythsec/services/pkg/versioninfo"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func run() error {
	var client clickhousewriter.Client
	flag.StringVar(&client.Binary, "client", "clickhouse-client", "官方 native 客户端可执行文件")
	flag.StringVar(&client.Host, "host", env("CLICKHOUSE_HOST", "127.0.0.1"), "ClickHouse 主机")
	flag.IntVar(&client.Port, "port", 9000, "native TCP 端口")
	flag.StringVar(&client.User, "user", env("CLICKHOUSE_USER", "default"), "用户；密码继承 CLICKHOUSE_PASSWORD")
	flag.StringVar(&client.Database, "database", "default", "目标库")
	flag.StringVar(&client.Table, "table", "flow_records_v1", "目标表")
	flag.BoolVar(&client.Secure, "secure", false, "使用 TLS native 连接")
	flag.DurationVar(&client.Timeout, "timeout", 10*time.Second, "单次 native 写入超时")
	spool := flag.String("spool", "", "持久化队列目录（必填，独占并绑定目标）")
	capacity := flag.Int64("max-pending-bytes", 64<<20, "含在途批次的队列文件字节上限")
	rows := flag.Int("batch-rows", 2000, "每批最大条数")
	batchBytes := flag.Int("batch-bytes", 4<<20, "每批 JSONL 最大字节（亦限制单条记录）")
	flush := flag.Duration("flush-interval", time.Second, "尾批最长等待")
	retry := flag.Duration("retry-interval", time.Second, "失败重试间隔")
	attempts := flag.Int("attempts", 3, "每批最多尝试次数，耗尽后保留队列并退出非零")
	inputPath := flag.String("input", "-", "JSONL 文件，- 为 stdin")
	resumeFile := flag.Bool("resume-file", false, "不可变文件的持久化输入断点（须指定 --input 文件）")
	replay := flag.Bool("replay-only", false, "只重放队列，不读取新输入")
	version := flag.Bool("version", false, "输出构建版本")
	flag.Parse()
	if *version {
		fmt.Println(versioninfo.String())
		return nil
	}
	if flag.NArg() != 0 {
		return errors.New("不接受位置参数")
	}
	if err := client.Validate(); err != nil {
		return err
	}
	if *rows <= 0 || *batchBytes <= 1 || *flush <= 0 {
		return errors.New("批次参数无效")
	}
	if *resumeFile && (*inputPath == "-" || *replay) {
		return errors.New("--resume-file 需要 --input 文件，不能与 --replay-only 同用")
	}
	q, err := clickhousewriter.Open(clickhousewriter.Config{Directory: *spool, Target: client.Target(), MaxPendingBytes: *capacity, RetryInterval: *retry, MaxAttempts: *attempts, ResumeFile: *resumeFile})
	if err != nil {
		return err
	}
	defer q.Close()
	defer func() { data, _ := json.Marshal(q.Stats()); fmt.Fprintf(os.Stderr, "[cythsec-ch-write] %s\n", data) }()
	var input io.Reader = os.Stdin
	var file *os.File
	if !*replay && *inputPath != "-" {
		file, err = os.Open(*inputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		input = file
		// 源文件身份不符时，在发出任何旧批次前拒绝启动。
		if *resumeFile {
			if err = q.BindFile(file); err != nil {
				return err
			}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { result := q.Run(workerCtx, client.Send); done <- result; cancel() }()
	// 先清空启动时已有的持久化批次，失败时不消费新输入。
	err = q.WaitEmpty(workerCtx)
	if err == nil && !*replay {
		if *resumeFile {
			err = q.ConsumeFile(workerCtx, file, *rows, *batchBytes)
		} else {
			err = clickhousewriter.Consume(workerCtx, input, *rows, *batchBytes, *flush, q.Enqueue)
		}
	}
	if err == nil {
		err = q.WaitEmpty(workerCtx)
	}
	cancel()
	workerErr := <-done
	if workerErr != nil && !errors.Is(workerErr, context.Canceled) {
		return workerErr
	}
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "写入未完成:", err)
		os.Exit(1)
	}
}
