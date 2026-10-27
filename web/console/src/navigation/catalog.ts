import routes, { type ConsoleProduct, type ConsoleRoute } from '../../config/routes';

export interface NavigationPage {
  path: string;
  name: string;
  product: ConsoleProduct;
  section: string;
}
export function collectPages(items: ConsoleRoute[], inherited?: ConsoleProduct): NavigationPage[] {
  return items.flatMap(route => {
    const product = route.consoleProduct ?? inherited;
    if (route.routes) return collectPages(route.routes, product);
    return route.component && route.name && product && route.path !== '*'
      ? [{ path: route.path, name: route.name, product, section: route.consoleSection ?? '功能菜单' }]
      : [];
  });
}
export const navigationPages = collectPages(routes);
export const navigationProducts = Array.from(new Map(navigationPages.map(page => [page.product.id, page.product])).values());
export function searchPages(pages: NavigationPage[], query: string) {
  const normalized = query.trim().toLocaleLowerCase();
  return pages.filter(page => `${page.name} ${page.product.name} ${page.section} ${page.path}`.toLocaleLowerCase().includes(normalized));
}

// Preferences contain published navigation paths only; never persist arbitrary URLs or traffic identifiers.
const storageKey = 'cythsec.console.navigation.v1';
export interface NavigationPreferences { favorites: string[]; recent: string[]; collapsed: boolean }
export function sanitizePreferences(value: unknown, pages = navigationPages): NavigationPreferences {
  const data = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  const paths = new Set(pages.map(page => page.path));
  const valid = (items: unknown, limit: number) => Array.isArray(items)
    ? Array.from(new Set(items.filter((item): item is string => typeof item === 'string' && paths.has(item)))).slice(0, limit) : [];
  return { favorites: valid(data.favorites, 50), recent: valid(data.recent, 8), collapsed: data.collapsed === true };
}
export function readPreferences(): NavigationPreferences {
  try { return sanitizePreferences(JSON.parse(localStorage.getItem(storageKey) ?? '{}')); }
  catch { return sanitizePreferences(null); }
}
export function writePreferences(value: NavigationPreferences) {
  try { localStorage.setItem(storageKey, JSON.stringify(sanitizePreferences(value))); }
  catch { /* Navigation remains usable when storage is disabled or full. */ }
}
