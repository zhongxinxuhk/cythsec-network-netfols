// 本文件提供 Go 运行时指标采集（goroutine 数、堆内存、GC 次数等）。
//
// 实现仅依赖标准库 runtime / runtime.ReadMemStats，不依赖
// runtime/metrics 的直方图结构，保持与 Go 1.22 兼容。
package metrics

import (
	"runtime"
)

// goRuntimeCollector 采集 Go 运行时指标。
//
// 采用「采集时读取」而非后台轮询，避免为指标引入额外 goroutine。
// ReadMemStats 会短暂 STW，在高 QPS 服务上应控制抓取频率（Prometheus 侧
// 通常 15s 一次，可忽略）。
type goRuntimeCollector struct {
	goroutines *Gauge
	heapAlloc  *Gauge
	heapInuse  *Gauge
	heapObjs   *Gauge
	sys        *Gauge
	gcCycles   *Counter // 采集时按差值累加
	lastGC     uint32
	mallocs    *Gauge
	frees      *Gauge
}

// goRuntimeCollectors 返回 Go 运行时指标族集合，供 RegisterGoCollector 注册。
func newGoRuntimeCollector() *goRuntimeCollector {
	return &goRuntimeCollector{
		goroutines: NewGauge("go", "goroutines", "count", "当前活跃的 goroutine 数量。"),
		heapAlloc:  NewGauge("go", "heap_alloc", "bytes", "已分配且在用的堆内存字节数。"),
		heapInuse:  NewGauge("go", "heap_inuse", "bytes", "堆内存中已使用的 span 字节数。"),
		heapObjs:   NewGauge("go", "heap_objects", "count", "堆上活跃对象数量。"),
		sys:        NewGauge("go", "sys", "bytes", "向操作系统申请的内存总字节数。"),
		gcCycles:   NewCounter("go", "gc_cycles", "total", "已完成的 GC 周期总数。"),
		mallocs:    NewGauge("go", "mallocs", "count", "累计堆分配对象数。"),
		frees:      NewGauge("go", "frees", "count", "累计堆释放对象数。"),
	}
}

// RegisterGoCollector 把 Go 运行时指标注册到 registry。
//
// 返回的 refresh 函数用于刷新瞬时值（ghc 次数按差值累加到 counter）。
// 调用方应在每次抓取前调用 refresh，或在启动时起一个短周期 goroutine 调用它。
func RegisterGoCollector(r *Registry) (refresh func()) {
	c := newGoRuntimeCollector()
	r.MustRegister(
		c.goroutines, c.heapAlloc, c.heapInuse, c.heapObjs,
		c.sys, c.gcCycles, c.mallocs, c.frees,
	)
	return c.refresh
}

// refresh 重新读取运行时统计并更新各指标。
//
// 注意：ReadMemStats 本身是测量动作，其开销主要来自 STW，故不宜高频调用。
func (c *goRuntimeCollector) refresh() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	c.goroutines.Set(float64(runtime.NumGoroutine()))
	c.heapAlloc.Set(float64(ms.HeapAlloc))
	c.heapInuse.Set(float64(ms.HeapInuse))
	c.heapObjs.Set(float64(ms.HeapObjects))
	c.sys.Set(float64(ms.Sys))
	c.mallocs.Set(float64(ms.Mallocs))
	c.frees.Set(float64(ms.Frees))

	// NumGC 单调递增；按差值累加，使对外呈 counter 语义。
	if ms.NumGC > c.lastGC {
		c.gcCycles.Add(uint64(ms.NumGC - c.lastGC))
		c.lastGC = ms.NumGC
	}
}
