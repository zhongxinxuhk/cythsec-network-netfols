import { matchRoutes } from 'react-router-dom';
import { expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import routes, { createConsoleRoutes, type ConsoleRoute } from '../config/routes';
const leaves = (items: ConsoleRoute[]): ConsoleRoute[] => items.flatMap(item => item.routes ? leaves(item.routes) : [item]);
const componentExists = (component: string) => {
  const location = component.startsWith('@/') ? resolve(__dirname, '../src', component.slice(2)) : resolve(__dirname, '../src/pages', component);
  return existsSync(`${location}.tsx`) || existsSync(resolve(location, 'index.tsx'));
};
it('真实业务页面、兼容入口和完整 Pro 页面共用 Umi 路由', () => {
  const pages = leaves(routes);
  for (const path of ['/network/overview', '/network/interfaces', '/network/routes', '/network/traffic', '/network/system', '/operations/network-configuration', '/operations/analytics', '/operations/metrics', '/operations/queue', '/dashboard/analysis', '/form/basic-form']) {
    expect(pages.find(route => route.path === path)?.component, path).toBeTruthy();
  }
  for (const path of ['interfaces', 'routes', 'traffic', 'system']) expect(pages.find(route => route.path === `/${path}`)?.redirect).toBe(`/network/${path}`);
  expect(new Set(routes.map(route => route.path)).size).toBe(routes.length);
  for (const route of pages.filter(route => route.component)) expect(componentExists(route.component!), route.component).toBe(true);
  expect(pages.some(route => route.path === '/*' && route.component)).toBe(true);
});
it('设计工作区只在开发环境启用且沿用共享布局', () => {
  const pages = leaves(createConsoleRoutes(true));
  expect(new Set(pages.map(route => route.path)).size).toBe(pages.length);
  expect(pages.filter(route => route.path.startsWith('/design/') && route.component)).toHaveLength(5);
  expect(pages.find(route => route.path === '/design')).toMatchObject({ redirect: '/design/overview' });
  for (const route of pages.filter(route => route.component)) {
    expect(componentExists(route.component!), route.component).toBe(true);
    expect(route.layout).not.toBe(true);
  }
  expect(createConsoleRoutes(false).some(route => route.path.startsWith('/design'))).toBe(false);
});

it('生产和开发完整路由树均可由真实路由器匹配', () => {
  for (const includeDesign of [false, true]) {
    const adapt = (items: ConsoleRoute[]): any[] => items.map(({ routes, ...route }) => ({ ...route, children: routes ? adapt(routes) : undefined }));
    const tree = adapt(createConsoleRoutes(includeDesign));
    expect(() => matchRoutes(tree, '/dashboard/analysis')).not.toThrow();
    expect(matchRoutes(tree, '/operations/network-configuration')?.at(-1)?.route.component).toBe('./NetworkConfigurationPage');
  }
});
