import type { ReactNode } from 'react';
import { ProCard } from '@ant-design/pro-components';
import { Alert, Typography } from 'antd';
interface Props { title: string; subtitle?: string; loading?: boolean; error?: string | null; children: ReactNode }
export function Card({ title, subtitle, loading, error, children }: Props) {
  return <ProCard title={title} loading={loading} variant="outlined">
    {subtitle && <Typography.Paragraph type="secondary">{subtitle}</Typography.Paragraph>}
    {error ? <Alert type="error" title={error} showIcon role="alert" /> : children}
  </ProCard>;
}
