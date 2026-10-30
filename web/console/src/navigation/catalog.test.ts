import { expect, it } from 'vitest';
import {
  navigationPages,
  navigationProducts,
  sanitizePreferences,
  searchPages,
} from './catalog';

it('keeps all product pages while excluding auth redirects and wildcard routes', () => {
  expect(navigationPages.some((p) => p.path === '/network/routes')).toBe(true);
  expect(navigationPages.some((p) => p.path === '/dashboard/analysis')).toBe(
    true,
  );
  expect(
    navigationPages.some(
      (p) => p.path.startsWith('/user') || p.path.includes('*'),
    ),
  ).toBe(false);
  expect(navigationProducts.length).toBeGreaterThan(8);
  expect(new Set(navigationPages.map((p) => p.path)).size).toBe(
    navigationPages.length,
  );
});
it('searches names and paths, and persists only known navigation paths', () => {
  expect(searchPages(navigationPages, '路由表').map((p) => p.path)).toEqual([
    '/network/routes',
  ]);
  const p = sanitizePreferences({
    favorites: ['https://example.com', '/network/routes', '/network/routes'],
    recent: ['/missing', '/dashboard/analysis', '/interfaces'],
    collapsed: true,
  });
  expect(p.favorites).toEqual(['/network/routes']);
  expect(p.recent).toEqual(['/dashboard/analysis', '/network/interfaces']);
  expect(p.collapsed).toBe(true);
});
