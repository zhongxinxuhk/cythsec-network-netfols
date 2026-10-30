import { Badge, Space, Tooltip } from 'antd';
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
  return <Space>
    {([['routerd', router], ['telemetryd', telemetry]] as const).map(([name, state]) => {
      const label = `${name} ${state.error ? 'offline' : state.data ? 'online' : '检查中'}`;
      return <Tooltip title={label} key={name}>
        <span role="status" aria-label={label}><Badge status={state.error ? 'error' : state.data ? 'success' : 'default'} /> <span className="header-service-label">{label}</span></span>
      </Tooltip>;
    })}
  </Space>;
}
