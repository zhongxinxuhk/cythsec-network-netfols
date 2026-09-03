// SystemPage.tsx - 系统概貌页。
import { api } from '@/api/client';
import type { SystemInfo } from '@/api/types';
import { Card } from '@/components/Card';
import { useApi } from '@/hooks/useApi';

function Row({ k, v }: { k: string; v: string | number }) {
  return (
    <div className="kv">
      <span className="kv-k">{k}</span>
      <span className="kv-v">{String(v)}</span>
    </div>
  );
}

export function SystemPage() {
  const { data, loading, error, reload } = useApi<SystemInfo>(() => api.system());
  return (
    <div className="page">
      <Card
        title="系统概貌"
        subtitle="routerd 运行所在主机 / 进程信息"
        loading={loading}
        error={error}
      >
        {data && (
          <div className="kv-list">
            <Row k="主机名 hostname" v={data.hostname} />
            <Row k="操作系统 os" v={`${data.os} / ${data.arch}`} />
            <Row k="Go 版本" v={data.go_version} />
            <Row k="进程 pid" v={data.pid} />
          </div>
        )}
        {!loading && (
          <button className="btn" onClick={reload}>
            刷新
          </button>
        )}
      </Card>
    </div>
  );
}
