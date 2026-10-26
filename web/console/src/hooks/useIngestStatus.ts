import { useEffect, useState } from 'react';
import { analytics } from '@/api/analytics';
import type { IngestStatus } from '@/api/analytics';

export function useIngestStatus() {
  const [status, setStatus] = useState<IngestStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let stopped = false;
    let controller: AbortController | null = null;
    const load = async () => {
      controller?.abort(); controller = new AbortController();
      const active = controller;
      const timeout = window.setTimeout(() => {
        if (!stopped && !active.signal.aborted) {
          active.abort(); setStatus(null); setError('队列状态请求超时');
        }
      }, 2500);
      try {
        const value = await analytics.ingest(active.signal);
        if (!stopped && !active.signal.aborted) { setStatus(value); setError(null); }
      } catch (e) {
        if (!stopped && !active.signal.aborted) { setStatus(null); setError(e instanceof Error ? e.message : '查询失败'); }
      } finally { window.clearTimeout(timeout); }
    };
    void load();
    const timer = window.setInterval(() => void load(), 3000);
    return () => { stopped = true; controller?.abort(); window.clearInterval(timer); };
  }, []);
  return { status, error };
}
