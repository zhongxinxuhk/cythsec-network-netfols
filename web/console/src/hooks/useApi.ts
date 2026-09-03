// useApi.ts - 通用数据拉取 hook：loading / error / data，支持可选轮询。
import { useCallback, useEffect, useState } from 'react';

interface State<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

export function useApi<T>(fetcher: () => Promise<T>, pollMs?: number): State<T> & { reload: () => void } {
  const [state, setState] = useState<State<T>>({
    data: null,
    loading: true,
    error: null,
  });

  const load = useCallback(async () => {
    setState((s) => ({ ...s, loading: true }));
    try {
      const data = await fetcher();
      setState({ data, loading: false, error: null });
    } catch (e) {
      setState({
        data: null,
        loading: false,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }, [fetcher]);

  useEffect(() => {
    void load();
    if (pollMs && pollMs > 0) {
      const id = window.setInterval(() => void load(), pollMs);
      return () => window.clearInterval(id);
    }
  }, [load, pollMs]);

  return { ...state, reload: load };
}
