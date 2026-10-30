import { Badge } from 'antd';
interface Props { tone: 'ok' | 'err' | 'warn' | 'muted'; label: string }
const statuses = { ok: 'success', err: 'error', warn: 'warning', muted: 'default' } as const;
export function StatusBadge({ tone, label }: Props) {
  return <Badge status={statuses[tone]} text={label} />;
}
