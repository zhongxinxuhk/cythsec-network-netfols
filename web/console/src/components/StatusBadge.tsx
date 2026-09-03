// StatusBadge.tsx - 语义化状态徽标（ok / error / warn / muted）。
interface Props {
  tone: 'ok' | 'err' | 'warn' | 'muted';
  label: string;
}

export function StatusBadge({ tone, label }: Props) {
  const cls =
    tone === 'ok' ? 'badge-ok' : tone === 'err' ? 'badge-err' : tone === 'warn' ? 'badge-warn' : 'badge-muted';
  return (
    <span className={`status-badge ${cls}`}>
      <span className="dot" />
      {label}
    </span>
  );
}
