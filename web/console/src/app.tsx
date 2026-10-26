import type { RunTimeLayoutConfig } from '@umijs/max';
import { HeaderStatus } from '@/components/HeaderStatus';
import { versionLabel } from '@/utils/version';

// 没有身份服务时不伪造登录用户、管理员角色或授权结果。
export const layout: RunTimeLayoutConfig = () => ({
  logo: '/logo.svg',
  avatarProps: undefined,
  actionsRender: () => [<HeaderStatus key="services" />],
  footerRender: () => <footer className="console-footer">CythSec · {versionLabel()} · 聚合运行监测</footer>,
  menu: { locale: false },
});
