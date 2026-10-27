import { expect, it } from 'vitest';
import { createConsoleRoutes } from '../../config/routes';
import { collectPages, sanitizePreferences, searchPages } from './catalog';

it('目录继承路由产品元数据且只发布实际页面，设计视图不进入生产导航', () => {
  const production = collectPages(createConsoleRoutes(false));
  const development = collectPages(createConsoleRoutes(true));
  expect(production).toHaveLength(8);
  expect(development).toHaveLength(13);
  expect(development.filter(page => page.product.id === 'design')).toHaveLength(5);
  expect(new Set(development.map(page => page.path)).size).toBe(13);
  expect(production.some(page => page.path.startsWith('/design'))).toBe(false);
  expect(searchPages(production, ' NETWORK ')).toEqual([]);
  expect(searchPages(production, '网络管理').map(page => page.path)).toEqual(['/interfaces', '/routes', '/traffic']);
  expect(searchPages(production, '/ROUTES')[0].name).toBe('路由表');
});
it('偏好只接受已发布路径，去重并限制最近访问，不保留任意URL或生产不可用页面', () => {
  const pages = collectPages(createConsoleRoutes(false));
  expect(sanitizePreferences({ favorites: ['/', '/', '/design/asset', 'https://example.com', '/analytics?ip=secret', null], recent: ['/system', '/system', '/routes'], collapsed: 'true' }, pages)).toEqual({ favorites: ['/'], recent: ['/system', '/routes'], collapsed: false });
  expect(sanitizePreferences(null, pages)).toEqual({ favorites: [], recent: [], collapsed: false });
});
