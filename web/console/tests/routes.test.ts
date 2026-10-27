import { expect, it, vi } from 'vitest';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import routes, { createConsoleRoutes, type ConsoleRoute } from '../config/routes';
vi.mock('@umijs/max', async () => {
  const router = await import('react-router-dom');
  return { Link: router.Link, useLocation: router.useLocation };
});
import { layout } from '../src/app';

const leaves = (items: ConsoleRoute[]): ConsoleRoute[] => items.flatMap(item => item.routes ? leaves(item.routes) : [item]);

it('运行时明确应用共享Pro外壳，服务操作不落入旧版侧栏渲染器', () => {
  expect(layout({} as Parameters<typeof layout>[0])).toMatchObject({
    layout: 'mix', siderWidth: 272, fixedHeader: true, fixSiderbar: false,
    rightContentRender: false, headerRender: expect.any(Function), menuRender: expect.any(Function),
  });
});
it('Pro 菜单与真实页面使用同一份 Umi 路由配置，保留既有入口并发布字典和队列及独立404', () => {
  expect(routes.filter((route) => route.name).map((route) => route.path)).toEqual(['/', '/interfaces', '/routes', '/traffic', '/network/configuration', '/analytics', '/analytics/metrics', '/data/queue', '/system']);
  expect(new Set(routes.map((route) => route.path)).size).toBe(routes.length);
  for (const route of routes) {
    expect(route.component).toBeDefined();
    expect(existsSync(resolve(__dirname, '../src/pages', `${route.component}.tsx`))).toBe(true);
  }
  expect(routes[routes.length - 1]).toMatchObject({ path: '*', layout: false });
});

it('开发设计视图共用一份路由，生产路由不包含样例工作区', () => {
  const development = createConsoleRoutes(true);
  const pages = leaves(development);
  expect(new Set(pages.map(route => route.path)).size).toBe(pages.length);
  expect(pages.filter(route => route.path.startsWith('/design/') && route.component)).toHaveLength(5);
  expect(pages.find(route => route.path === '/design')).toMatchObject({ redirect: '/design/overview' });
  for (const route of pages.filter(route => route.component)) {
    const component = route.component ?? '';
    expect(component).not.toBe('');
    const location = component.startsWith('@/') ? resolve(__dirname, '../src', `${component.slice(2)}.tsx`) : resolve(__dirname, '../src/pages', `${component}.tsx`);
    expect(existsSync(location)).toBe(true);
    expect(route.layout).not.toBe(true); // inherited Umi/Pro shell, no separate application layout
  }
  expect(createConsoleRoutes(false).some(route => route.path.startsWith('/design'))).toBe(false);
});
