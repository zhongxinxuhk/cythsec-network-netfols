import { expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import routes from '../config/routes';
it('Pro 菜单与真实页面使用同一份 Umi 路由配置，保留六个业务入口及独立404', () => {
  expect(routes.filter((route) => route.name).map((route) => route.path)).toEqual(['/', '/interfaces', '/routes', '/traffic', '/analytics', '/system']);
  expect(new Set(routes.map((route) => route.path)).size).toBe(routes.length);
  for (const route of routes) expect(existsSync(resolve(__dirname, '../src/pages', `${route.component}.tsx`))).toBe(true);
  expect(routes[routes.length - 1]).toMatchObject({ path: '*', layout: false });
});
