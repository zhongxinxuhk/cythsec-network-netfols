import routes from '../../config/routes';
import menu from '../locales/zh-CN/menu';

interface Route {
  path?: string;
  name?: string;
  component?: string;
  routes?: Route[];
  access?: string;
  hideInMenu?: boolean;
}
export interface NavigationProduct {
  id: string;
  name: string;
  icon: string;
  shortName: string;
}
export interface NavigationPage {
  path: string;
  name: string;
  product: NavigationProduct;
  section: string;
  access?: string;
}
const labels = menu as Record<string, string>;
const meta: Record<string, [string, string]> = {
  operations: ['SettingOutlined','运维'], network: ['ClusterOutlined', '网络'],
  welcome: ['DashboardOutlined', '帮助'],
  admin: ['SettingOutlined', '管理'],
  dashboard: ['DashboardOutlined', '仪表'],
  form: ['FormOutlined', '表单'],
  list: ['TableOutlined', '列表'],
  profile: ['ProfileOutlined', '详情'],
  result: ['CheckCircleOutlined', '结果'],
  exception: ['WarningOutlined', '异常'],
  account: ['UserOutlined', '账户'],
  chatbot: ['RobotOutlined', '助手'],
};
export function collectPages(items: Route[] = routes): NavigationPage[] {
  return items.flatMap((root) => {
    if (
      !root.name ||
      !root.path ||
      root.path.startsWith('/user') ||
      root.hideInMenu
    )
      return [];
    const [icon, shortName] = meta[root.name] ?? [
      'DashboardOutlined',
      root.name,
    ];
    const product = {
      id: root.name,
      name:
        root.name === 'dashboard'
          ? '仪表盘'
          : (labels[`menu.${root.name}`] ?? root.name),
      icon,
      shortName,
    };
    const visit = (
      route: Route,
      key: string,
      section: string,
      access?: string,
    ): NavigationPage[] => {
      if (route.hideInMenu) return [];
      const name = labels[`menu.${key}`] ?? route.name ?? product.name;
      if (route.routes)
        return route.routes.flatMap((child) =>
          visit(
            child,
            child.name ? `${key}.${child.name}` : key,
            route === root ? section : name,
            child.access ?? route.access ?? access,
          ),
        );
      return route.component &&
        route.name &&
        route.path &&
        !route.path.includes('*')
        ? [
            {
              path: route.path,
              name,
              product,
              section,
              access: route.access ?? access,
            },
          ]
        : [];
    };
    return visit(root, root.name, product.name, root.access);
  });
}
export const navigationPages = collectPages();
export const navigationProducts = Array.from(
  new Map(
    navigationPages.map((page) => [page.product.id, page.product]),
  ).values(),
);
export function searchPages(pages: NavigationPage[], query: string) {
  const normalized = query.trim().toLocaleLowerCase();
  return pages.filter((page) =>
    `${page.name} ${page.product.name} ${page.section} ${page.path}`
      .toLocaleLowerCase()
      .includes(normalized),
  );
}

// Preferences contain published navigation paths only; never persist arbitrary URLs or traffic identifiers.
const storageKey = 'cythsec.console.navigation.v1';
export interface NavigationPreferences {
  favorites: string[];
  recent: string[];
  collapsed: boolean;
}
export function sanitizePreferences(
  value: unknown,
  pages = navigationPages,
): NavigationPreferences {
  const data =
    value && typeof value === 'object'
      ? (value as Record<string, unknown>)
      : {};
  const paths = new Set(pages.map((page) => page.path));
  const valid = (items: unknown, limit: number) =>
    Array.isArray(items)
      ? Array.from(
          new Set(
            items
              .filter((item): item is string => typeof item === 'string')
              .map(
                (item) =>
                  ({
                    '/interfaces': '/network/interfaces',
                    '/routes': '/network/routes',
                    '/traffic': '/network/traffic',
                    '/system': '/network/system',
                  })[item] ?? item,
              )
              .filter((item) => paths.has(item)),
          ),
        ).slice(0, limit)
      : [];
  return {
    favorites: valid(data.favorites, 50),
    recent: valid(data.recent, 8),
    collapsed: data.collapsed === true,
  };
}
export function readPreferences(): NavigationPreferences {
  try {
    return sanitizePreferences(
      JSON.parse(localStorage.getItem(storageKey) ?? '{}'),
    );
  } catch {
    return sanitizePreferences(null);
  }
}
export function writePreferences(value: NavigationPreferences) {
  try {
    localStorage.setItem(
      storageKey,
      JSON.stringify(sanitizePreferences(value)),
    );
  } catch {
    /* Navigation remains usable when storage is disabled or full. */
  }
}
