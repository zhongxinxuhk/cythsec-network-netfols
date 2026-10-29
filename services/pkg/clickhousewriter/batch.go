package clickhousewriter

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"time"
)

// Consume 按行/字节/时间封批；读取协程最多领先一行，背压经 Enqueue 传回源。
func Consume(ctx context.Context, input io.Reader, rows, maxBytes int, interval time.Duration, enqueue func(context.Context, []byte) error) error {
	if rows <= 0 || maxBytes <= 1 || interval <= 0 {
		return errors.New("批次条数、字节与刷新间隔必须为正")
	}
	type item struct {
		data []byte
		err  error
	}
	lines := make(chan item)
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, min(4096, maxBytes)), maxBytes)
		for scanner.Scan() {
			data := bytes.TrimSpace(scanner.Bytes())
			if len(data) == 0 {
				continue
			}
			select {
			case lines <- item{data: append([]byte(nil), data...)}:
			case <-readCtx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			select {
			case lines <- item{err: err}:
			case <-readCtx.Done():
			}
		}
	}()
	var payload []byte
	n := 0
	timer := time.NewTimer(interval)
	timer.Stop()
	defer timer.Stop()
	var timerC <-chan time.Time
	flush := func() error {
		if n == 0 {
			return nil
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
		if err := enqueue(ctx, payload); err != nil {
			return err
		}
		payload = nil
		n = 0
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timerC:
			if err := flush(); err != nil {
				return err
			}
		case line, ok := <-lines:
			if !ok {
				return flush()
			}
			if line.err != nil {
				if err := flush(); err != nil {
					return err
				}
				return line.err
			}
			record := append(line.data, '\n')
			if _, err := rowCount(record); err != nil {
				if flushErr := flush(); flushErr != nil {
					return flushErr
				}
				return err
			}
			if len(record) > maxBytes {
				return errors.New("单条记录超过批次字节上限")
			}
			if n > 0 && len(payload)+len(record) > maxBytes {
				if err := flush(); err != nil {
					return err
				}
			}
			if n == 0 {
				timer.Reset(interval)
				timerC = timer.C
			}
			payload = append(payload, record...)
			n++
			if n >= rows || len(payload) >= maxBytes {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}
}
