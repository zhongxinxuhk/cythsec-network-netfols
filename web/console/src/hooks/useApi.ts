import { useCallback, useEffect, useRef, useState } from 'react';
interface State<T> { data: T | null; loading: boolean; error: string | null }
export function useApi<T>(fetcher: () => Promise<T>, pollMs?: number): State<T> & { reload: () => void } {
  const [state, setState] = useState<State<T>>({ data: null, loading: true, error: null });
  const currentFetcher = useRef(fetcher);
  currentFetcher.current = fetcher;
  const generation = useRef(0);
  const load = useCallback(async () => {
    const request = ++generation.current;
    setState((old) => ({ ...old, loading: true }));
    try {
      const data = await currentFetcher.current();
      if (request === generation.current) setState({ data, loading: false, error: null });
    } catch (error) {
      if (request === generation.current) setState({ data: null, loading: false, error: error instanceof Error ? error.message : String(error) });
    }
  }, []);
  useEffect(() => {
    const lifecycle = generation;
    void load();
    const timer = pollMs ? window.setInterval(() => void load(), pollMs) : undefined;
    return () => { lifecycle.current++; window.clearInterval(timer); };
  }, [load, pollMs]);
  return { ...state, reload: load };
}
