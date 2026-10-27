import type { ReactNode } from 'react';
import { AccessBoundary, ServiceAccess } from '@/components/ServiceAccess';
import type { RunTimeLayoutConfig } from '@umijs/max';
import { HeaderStatus } from '@/components/HeaderStatus';
import { versionLabel } from '@/utils/version';

// 身份与权限由真实服务返回，未启用鉴权时明确展示。
export const rootContainer = (children: ReactNode) => <AccessBoundary>{children}</AccessBoundary>;
export const layout: RunTimeLayoutConfig = () => ({
  // Umi's generated layout forwards title/locale from static config only.
  // Apply Pro layout settings here, and disable its legacy right-content renderer.
  layout: 'mix',
  navTheme: 'light',
  splitMenus: false,
  fixedHeader: true,
  fixSiderbar: true,
  siderWidth: 224,
  rightContentRender: false,
  logo: '/logo.svg',
  avatarProps: undefined,
  actionsRender: () => [<HeaderStatus key="services" />, <ServiceAccess key="access" />],
  footerRender: () => <footer className="console-footer">CythSec · {versionLabel()} · 聚合运行监测</footer>,
  menu: { locale: false },
});
