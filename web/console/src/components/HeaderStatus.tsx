import { Space } from 'antd';
import { StatusBadge } from './StatusBadge';
import { useApi } from '@/hooks/useApi';

async function health(url: string) {
  const response = await fetch(url, { signal: AbortSignal.timeout(2500) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return true;
}
const routerd = () => health('/healthz');
const telemetryd = () => health('/telemetry/healthz');
export function HeaderStatus() {
  const router = useApi(routerd, 5000);
  const telemetry = useApi(telemetryd, 5000);
  return <Space wrap>
    <StatusBadge tone={router.error ? 'err' : router.data ? 'ok' : 'muted'} label={`routerd ${router.error ? 'offline' : router.data ? 'online' : '检查中'}`} />
    <StatusBadge tone={telemetry.error ? 'err' : telemetry.data ? 'ok' : 'muted'} label={`telemetryd ${telemetry.error ? 'offline' : telemetry.data ? 'online' : '检查中'}`} />
  </Space>;
}
