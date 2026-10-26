import type { ReactNode } from 'react';
import { AccessBoundary, ServiceAccess } from '@/components/ServiceAccess';
import type { RunTimeLayoutConfig } from '@umijs/max';
import { HeaderStatus } from '@/components/HeaderStatus';
import { versionLabel } from '@/utils/version';

// 身份与权限由真实服务返回，未启用鉴权时明确展示。
export const rootContainer = (children: ReactNode) => <AccessBoundary>{children}</AccessBoundary>;
export const layout: RunTimeLayoutConfig = () => ({
  logo: '/logo.svg',
  avatarProps: undefined,
  actionsRender: () => [<HeaderStatus key="services" />, <ServiceAccess key="access" />],
  footerRender: () => <footer className="console-footer">CythSec · {versionLabel()} · 聚合运行监测</footer>,
  menu: { locale: false },
});
