package clickhousewriter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// sourceState 记录“已由持久化队列接收”的偏移，不是网络发送次数。
type sourceState struct {
	Version  int    `json:"version"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Offset   int64  `json:"offset"`
	Rows     uint64 `json:"rows"`
	Checksum string `json:"checksum"`
}

type sourceRange struct {
	SHA256   string `json:"sha256"`
	Start    int64  `json:"start"`
	End      int64  `json:"end"`
	Checksum string `json:"checksum"`
}

func checksum(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func stateChecksum(s sourceState) string { s.Checksum = ""; return checksum(s) }
func rangeChecksum(r sourceRange, dataSHA string) string {
	r.Checksum = ""
	return checksum(struct {
		Range   sourceRange
		DataSHA string
	}{r, dataSHA})
}

func (q *Queue) loadSource() error {
	data, err := os.ReadFile(filepath.Join(q.cfg.Directory, ".source"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var s sourceState
	if err = json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("源文件检查点损坏: %w", err)
	}
	if s.Version != 1 || s.Path == "" || len(s.SHA256) != 64 || s.Size < 0 || s.Offset < 0 || s.Offset > s.Size || s.Checksum != stateChecksum(s) {
		return errors.New("源文件检查点版本/范围/校验失败")
	}
	q.source = &s
	return nil
}

func (q *Queue) saveSource(s sourceState) error {
	s.Checksum = stateChecksum(s)
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err = q.atomicWrite(".source", data); err != nil {
		return err
	}
	q.source = &s
	return nil
}

func (q *Queue) validateRange(b batch) error {
	if b.Source == nil {
		if q.source != nil {
			return errors.New("断点队列禁止混入无源偏移的批次")
		}
		return nil
	}
	r := b.Source
	if q.source == nil || r.SHA256 != q.source.SHA256 || r.Start < 0 || r.End <= r.Start || r.End > q.source.Size || r.Checksum != rangeChecksum(*r, b.SHA256) {
		return errors.New("批次源文件/字节范围/校验不匹配")
	}
	return nil
}

// 批次已同步而 .source 未更新的窗口：从完整批次恢复连续高水位，发送前先保存检查点。
func (q *Queue) recoverSource(batches []batch) error {
	if q.source == nil {
		return nil
	}
	sort.Slice(batches, func(i, j int) bool { return batches[i].Source.Start < batches[j].Source.Start })
	next := *q.source
	lastEnd := int64(-1)
	for _, b := range batches {
		r := b.Source
		if r.Start < lastEnd {
			return errors.New("待重放批次的源字节范围重叠")
		}
		lastEnd = r.End
		if r.End <= next.Offset {
			continue
		}
		if r.Start != next.Offset {
			return errors.New("检查点与待重放批次间有缺口或重叠")
		}
		next.Offset = r.End
		next.Rows += uint64(b.Rows)
	}
	if next.Offset != q.source.Offset {
		return q.saveSource(next)
	}
	return nil
}

func identity(f *os.File) (sourceState, error) {
	info, err := f.Stat()
	if err != nil {
		return sourceState{}, err
	}
	if !info.Mode().IsRegular() {
		return sourceState{}, errors.New("断点输入必须是已发布的普通文件")
	}
	path, err := filepath.Abs(f.Name())
	if err != nil {
		return sourceState{}, err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return sourceState{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return sourceState{}, err
	}
	after, err := f.Stat()
	if err != nil {
		return sourceState{}, err
	}
	current, err := os.Stat(path)
	if err != nil {
		return sourceState{}, err
	}
	if !os.SameFile(after, current) {
		return sourceState{}, errors.New("源文件路径已被替换")
	}
	if n != info.Size() || after.Size() != n || !after.ModTime().Equal(info.ModTime()) {
		return sourceState{}, errors.New("源文件在校验时发生变化")
	}
	return sourceState{Version: 1, Path: path, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// BindFile 在启动消费者之前校验不可变源；已有批次的普通队列不能直接切换为断点模式。
func (q *Queue) BindFile(f *os.File) error {
	s, err := identity(f)
	if err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.fatal != nil {
		return errors.New("队列已关闭或有持久化错误")
	}
	if q.source == nil {
		if q.stats.PendingBatches != 0 {
			return errors.New("普通队列仍有批次，不能启用文件断点")
		}
		return q.saveSource(s)
	}
	old := q.source
	if old.Path != s.Path || old.Size != s.Size || old.SHA256 != s.SHA256 {
		return errors.New("源文件路径/长度/SHA256 已变化，拒绝沿用断点")
	}
	return nil
}

// ConsumeFile 只处理已完成、不可变文件；支持 CRLF、空白行和末行无换行，不追踪追加。
func (q *Queue) ConsumeFile(ctx context.Context, f *os.File, rows, maxBytes int) error {
	if rows <= 0 || maxBytes <= 1 {
		return errors.New("批次参数无效")
	}
	if err := q.BindFile(f); err != nil {
		return err
	}
	q.mu.Lock()
	initial := *q.source
	q.mu.Unlock()
	if initial.Offset > 0 && initial.Offset < initial.Size {
		b := []byte{0}
		if _, err := f.ReadAt(b, initial.Offset-1); err != nil {
			return err
		}
		if b[0] != '\n' {
			return errors.New("检查点没有落在记录边界")
		}
	}
	if _, err := f.Seek(initial.Offset, io.SeekStart); err != nil {
		return err
	}
	offset, start := initial.Offset, initial.Offset
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, min(4096, maxBytes)), maxBytes)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		advance, token, err := bufio.ScanLines(data, atEOF)
		offset += int64(advance)
		return advance, token, err
	})
	var payload []byte
	n := 0
	flush := func(end int64) error {
		if n == 0 {
			return nil
		}
		if err := q.enqueue(ctx, payload, &sourceRange{SHA256: initial.SHA256, Start: start, End: end}); err != nil {
			return err
		}
		start = end
		payload = nil
		n = 0
		return nil
	}
	for {
		before := offset
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				if e := flush(before); e != nil {
					return e
				}
				return err
			}
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		record := append(append([]byte(nil), line...), '\n')
		if _, err := rowCount(record); err != nil {
			if e := flush(before); e != nil {
				return e
			}
			return err
		}
		if len(record) > maxBytes {
			if e := flush(before); e != nil {
				return e
			}
			return errors.New("记录超过批次字节上限")
		}
		if n > 0 && len(payload)+len(record) > maxBytes {
			if err := flush(before); err != nil {
				return err
			}
		}
		payload = append(payload, record...)
		n++
		if n >= rows {
			if err := flush(offset); err != nil {
				return err
			}
		}
	}
	if err := flush(offset); err != nil {
		return err
	}
	// EOF 再校验，拒绝处理期间被替换/追加/改写的源文件。
	if err := q.BindFile(f); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if q.fatal != nil {
		return q.fatal
	}
	if offset != initial.Size {
		return errors.New("源文件实际结束位置与发布长度不一致")
	}
	// 末尾仅有空白行时，没有待发送数据，但仍须确认已扫描的字节。
	if q.source.Offset < offset {
		next := *q.source
		next.Offset = offset
		if err := q.saveSource(next); err != nil {
			q.fatal = err
			q.notify()
			return err
		}
	}
	return nil
}
