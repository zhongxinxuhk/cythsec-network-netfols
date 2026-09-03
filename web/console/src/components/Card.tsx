// Card.tsx - 数据面板卡片，统一承载标题、加载态、错误态与内容。
import type { ReactNode } from 'react';

interface Props {
  title: string;
  subtitle?: string;
  loading?: boolean;
  error?: string | null;
  children: ReactNode;
}

export function Card({ title, subtitle, loading, error, children }: Props) {
  return (
    <section className="card">
      <header className="card-head">
        <h2>{title}</h2>
        {subtitle && <p>{subtitle}</p>}
      </header>
      <div className="card-body">
        {loading ? (
          <p className="muted">加载中…</p>
        ) : error ? (
          <p className="error-text">{error}</p>
        ) : (
          children
        )}
      </div>
    </section>
  );
}
