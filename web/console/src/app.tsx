import type { ReactNode } from 'react';
import { AccessBoundary } from '@/components/ServiceAccess';
import type { RunTimeLayoutConfig } from '@umijs/max';
import { CloudHeader, CloudNavigation } from '@/navigation/CloudConsole';
import { NavigationProvider } from '@/navigation/NavigationProvider';
import { versionLabel } from '@/utils/version';

// 身份与权限由真实服务返回，未启用鉴权时明确展示。
export const rootContainer = (children: ReactNode) => <AccessBoundary><NavigationProvider>{children}</NavigationProvider></AccessBoundary>;
export const layout: RunTimeLayoutConfig = () => ({
  // Umi's generated layout forwards title/locale from static config only.
  // Apply Pro layout settings here, and disable its legacy right-content renderer.
  layout: 'mix',
  navTheme: 'light',
  splitMenus: false,
  fixedHeader: true,
  fixSiderbar: false,
  siderWidth: 272,
  collapsed: false,
  // Quoted public theme key distinguishes visual tokens from credential assignments.
  'token': { header: { heightLayoutHeader: 50 } },
  contentStyle: { minWidth: 0, margin: 0 },
  headerRender: () => <CloudHeader />,
  menuRender: () => <CloudNavigation />,
  rightContentRender: false,
  logo: '/logo.svg',
  avatarProps: undefined,
  footerRender: () => <footer className="console-footer">CythSec · {versionLabel()} · 聚合运行监测</footer>,
  menu: { locale: false },
});
