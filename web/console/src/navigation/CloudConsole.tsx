import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { Link, useLocation, useAccess } from '@umijs/max';
import {
  AppstoreOutlined,
  BarChartOutlined,
  ClusterOutlined,
  DashboardOutlined,
  ExperimentOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SearchOutlined,
  SettingOutlined,
  StarFilled,
  StarOutlined,
  FormOutlined,
  TableOutlined,
  ProfileOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  UserOutlined,
  RobotOutlined,
} from '@ant-design/icons';
import {
  Button,
  ConfigProvider,
  Drawer,
  Empty,
  Input,
  Menu,
  Tabs,
  Tooltip,
  Typography,
  theme,
} from 'antd';
import {
  navigationPages as allPages,
  searchPages,
  type NavigationPage,
} from './catalog';
import { useConsoleNavigation } from './NavigationProvider';
import './cloud-console.css';

const icons: Record<string, ReactNode> = {
  FormOutlined: <FormOutlined />,
  TableOutlined: <TableOutlined />,
  ProfileOutlined: <ProfileOutlined />,
  CheckCircleOutlined: <CheckCircleOutlined />,
  WarningOutlined: <WarningOutlined />,
  UserOutlined: <UserOutlined />,
  RobotOutlined: <RobotOutlined />,
  DashboardOutlined: <DashboardOutlined />,
  ClusterOutlined: <ClusterOutlined />,
  BarChartOutlined: <BarChartOutlined />,
  SettingOutlined: <SettingOutlined />,
  ExperimentOutlined: <ExperimentOutlined />,
};
function useVisiblePages() {
  const access = useAccess() as Record<string, boolean>;
  return useMemo(
    () => allPages.filter((page) => !page.access || access[page.access]),
    [access],
  );
}
function productsFor(pages: NavigationPage[]) {
  return Array.from(
    new Map(pages.map((page) => [page.product.id, page.product])).values(),
  );
}
function useCurrentPage() {
  const navigationPages = useVisiblePages();
  const { pathname } = useLocation();
  return navigationPages.find((page) => page.path === pathname);
}
function useCloseOnNavigation() {
  const navigationPages = useVisiblePages();
  const { pathname } = useLocation();
  const { setCatalogOpen, setMobileOpen, setPreferences } =
    useConsoleNavigation();
  useLayoutEffect(() => {
    setCatalogOpen(false);
    setMobileOpen(false);
  }, [pathname, setCatalogOpen, setMobileOpen]);
  useEffect(() => {
    if (navigationPages.some((page) => page.path === pathname)) {
      setPreferences((previous) =>
        previous.recent[0] === pathname
          ? previous
          : {
              ...previous,
              recent: [
                pathname,
                ...previous.recent.filter((path) => path !== pathname),
              ].slice(0, 8),
            },
      );
    }
  }, [pathname, setPreferences, navigationPages]);
}
function PageLinks({ pages }: { pages: NavigationPage[] }) {
  const { preferences, setPreferences, setCatalogOpen } =
    useConsoleNavigation();
  const current = useCurrentPage();
  return (
    <div className="catalog-links">
      {pages.map((page) => {
        const favorite = preferences.favorites.includes(page.path);
        return (
          <div className="catalog-link" key={page.path}>
            <Link
              className="catalog-page"
              to={page.path}
              onClick={() => setCatalogOpen(false)}
              aria-current={current?.path === page.path ? 'page' : undefined}
            >
              {page.name}
            </Link>
            <Tooltip title={favorite ? '取消收藏' : '收藏'}>
              <Button
                type="text"
                size="small"
                aria-label={`${favorite ? '取消收藏' : '收藏'}${page.product.name} · ${page.name}`}
                aria-pressed={favorite}
                icon={favorite ? <StarFilled /> : <StarOutlined />}
                onClick={() =>
                  setPreferences((previous) => ({
                    ...previous,
                    favorites: favorite
                      ? previous.favorites.filter((path) => path !== page.path)
                      : [...previous.favorites, page.path],
                  }))
                }
              />
            </Tooltip>
          </div>
        );
      })}
    </div>
  );
}
function ProductCatalog() {
  const navigationPages = useVisiblePages();
  const navigationProducts = productsFor(navigationPages);
  const { catalogOpen, setCatalogOpen, query, setQuery, preferences } =
    useConsoleNavigation();
  const [category, setCategory] = useState('all');
  const [tab, setTab] = useState('all');
  const source =
    tab === 'favorites'
      ? navigationPages.filter((page) =>
          preferences.favorites.includes(page.path),
        )
      : tab === 'recent'
        ? preferences.recent.flatMap((path) =>
            navigationPages.filter((page) => page.path === path),
          )
        : navigationPages;
  const pages = searchPages(
    source.filter((page) => category === 'all' || page.product.id === category),
    query,
  );
  const groups = navigationProducts.filter((product) =>
    pages.some((page) => page.product.id === product.id),
  );
  const content = pages.length ? (
    <div className="catalog-groups">
      {groups.map((product) => (
        <section
          className="catalog-group"
          key={product.id}
          aria-label={product.name}
        >
          <Typography.Title level={5}>
            {icons[product.icon]} {product.name}
          </Typography.Title>
          {Array.from(
            new Set(
              pages
                .filter((page) => page.product.id === product.id)
                .map((page) => page.section),
            ),
          ).map((section) => (
            <div key={section}>
              <Typography.Text type="secondary" className="catalog-section">
                {section}
              </Typography.Text>
              <PageLinks
                pages={pages.filter(
                  (page) =>
                    page.product.id === product.id && page.section === section,
                )}
              />
            </div>
          ))}
        </section>
      ))}
    </div>
  ) : (
    <Empty
      image={Empty.PRESENTED_IMAGE_SIMPLE}
      description={
        query
          ? '没有匹配的功能'
          : tab === 'favorites'
            ? '暂无收藏'
            : '暂无访问记录'
      }
    />
  );
  return (
    <Drawer
      destroyOnHidden
      title="产品与服务"
      placement="left"
      size="min(1040px, 100vw)"
      open={catalogOpen}
      onClose={() => setCatalogOpen(false)}
      styles={{
        wrapper: { top: 50, height: 'calc(100% - 50px)' },
        body: { padding: 0 },
      }}
    >
      <div className="catalog-layout">
        <nav className="catalog-categories" aria-label="功能分类">
          <Menu
            selectedKeys={[category]}
            onClick={({ key }) => setCategory(key)}
            items={[
              { key: 'all', icon: <AppstoreOutlined />, label: '全部功能' },
              ...navigationProducts.map((product) => ({
                key: product.id,
                icon: icons[product.icon],
                label: product.name,
              })),
            ]}
          />
        </nav>
        <div className="catalog-content">
          <Input
            allowClear
            autoFocus
            prefix={<SearchOutlined />}
            aria-label="搜索全部功能"
            placeholder="搜索功能、模块"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <Tabs
            activeKey={tab}
            onChange={setTab}
            destroyOnHidden
            items={[
              { key: 'all', label: '全部功能' },
              { key: 'favorites', label: '我的收藏' },
              { key: 'recent', label: '最近访问' },
            ].map((item) => ({ ...item, children: content }))}
          />
        </div>
      </div>
    </Drawer>
  );
}
export function CloudHeader({ actions }: { actions?: ReactNode }) {
  const { setCatalogOpen, setQuery, setMobileOpen } = useConsoleNavigation();
  const openCatalog = () => {
    setQuery('');
    setCatalogOpen(true);
    setMobileOpen(false);
  };
  return (
    <>
      <div className="cloud-header">
        <Tooltip title="产品与服务">
          <Button
            type="text"
            className="cloud-catalog-trigger"
            aria-label="打开产品与服务"
            icon={<AppstoreOutlined />}
            onClick={openCatalog}
          />
        </Tooltip>
        <Link className="cloud-brand" to="/">
          <img src="/cythsec.svg" alt="" />
          <strong>CythSec</strong>
          <span>控制台</span>
        </Link>
        <div className="cloud-header-divider" />
        <Link className="cloud-home" to="/dashboard/workplace">
          工作台
        </Link>
        <Button
          type="text"
          className="cloud-search"
          aria-label="搜索功能"
          icon={<SearchOutlined />}
          onClick={openCatalog}
        >
          <span className="cloud-search-label">搜索功能</span>
        </Button>
        <div className="cloud-header-services">{actions}</div>
        <Button
          type="text"
          className="cloud-mobile-trigger"
          aria-label="打开当前模块菜单"
          icon={<MenuUnfoldOutlined />}
          onClick={() => setMobileOpen(true)}
        />
      </div>
      <ProductCatalog />
    </>
  );
}
function ContextMenu({ showHeading = true }: { showHeading?: boolean }) {
  const navigationPages = useVisiblePages();
  const navigationProducts = productsFor(navigationPages);
  const current = useCurrentPage();
  const [query, setQuery] = useState('');
  const { setMobileOpen } = useConsoleNavigation();
  const product = current?.product ?? navigationProducts[0];
  const pages = searchPages(
    navigationPages.filter((page) => page.product.id === product.id),
    query,
  );
  const sections = Array.from(new Set(pages.map((page) => page.section)));
  return (
    <div className="context-menu-content">
      {showHeading && (
        <div className="context-menu-heading">
          <Typography.Title level={5}>{product.name}</Typography.Title>
        </div>
      )}
      <div className="context-menu-search">
        <Input
          allowClear
          prefix={<SearchOutlined />}
          placeholder="搜索当前模块"
          aria-label="搜索当前模块"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>
      <nav
        className="context-menu-scroll"
        aria-label={`${product.name}功能菜单`}
      >
        {pages.length ? (
          <Menu
            mode="inline"
            selectedKeys={current ? [current.path] : []}
            defaultOpenKeys={sections}
            key={`${product.id}:${query}`}
            onClick={() => setMobileOpen(false)}
            items={sections.map((section) => ({
              key: section,
              label: section,
              children: pages
                .filter((page) => page.section === section)
                .map((page) => ({
                  key: page.path,
                  label: (
                    <Link
                      to={page.path}
                      aria-current={
                        page.path === current?.path ? 'page' : undefined
                      }
                    >
                      {page.name}
                    </Link>
                  ),
                })),
            }))}
          />
        ) : (
          <Empty
            image={Empty.PRESENTED_IMAGE_SIMPLE}
            description="没有匹配的功能"
          />
        )}
      </nav>
    </div>
  );
}
export function CloudNavigation() {
  const navigationPages = useVisiblePages();
  const navigationProducts = productsFor(navigationPages);
  const current = useCurrentPage();
  const { preferences, setPreferences, mobileOpen, setMobileOpen } =
    useConsoleNavigation();
  const { token } = theme.useToken();
  useCloseOnNavigation();
  return (
    <ConfigProvider
      theme={{
        components: {
          Menu: { itemBorderRadius: 2, subMenuItemBorderRadius: 2 },
        },
      }}
    >
      <div
        className={`cloud-navigation-slot ${preferences.collapsed ? 'is-collapsed' : ''}`}
        style={{
          background: token.colorBgContainer,
          borderColor: token.colorBorderSecondary,
        }}
      >
        <aside
          className="cloud-navigation"
          aria-label="控制台导航"
          style={{
            background: token.colorBgContainer,
            borderColor: token.colorBorderSecondary,
          }}
        >
          <nav
            className="product-rail"
            aria-label="模块快捷导航"
            style={{ borderColor: token.colorBorderSecondary }}
          >
            <div className="product-rail-links">
              {navigationProducts.map((product) => {
                const page = navigationPages.find(
                  (item) => item.product.id === product.id,
                );
                return (
                  page && (
                    <Tooltip
                      title={product.name}
                      placement="right"
                      key={product.id}
                    >
                      <Link
                        to={page.path}
                        className={`product-rail-link ${current?.product.id === product.id ? 'is-active' : ''}`}
                        aria-label={product.name}
                        aria-current={
                          current?.product.id === product.id
                            ? 'true'
                            : undefined
                        }
                        style={{
                          color:
                            current?.product.id === product.id
                              ? token.colorPrimary
                              : token.colorTextSecondary,
                          background:
                            current?.product.id === product.id
                              ? token.colorPrimaryBg
                              : undefined,
                        }}
                      >
                        {icons[product.icon]}
                        <span>{product.shortName}</span>
                      </Link>
                    </Tooltip>
                  )
                );
              })}
            </div>
            <Tooltip
              title={preferences.collapsed ? '展开功能菜单' : '收起功能菜单'}
              placement="right"
            >
              <Button
                type="text"
                aria-label={
                  preferences.collapsed ? '展开功能菜单' : '收起功能菜单'
                }
                aria-expanded={!preferences.collapsed}
                icon={
                  preferences.collapsed ? (
                    <MenuUnfoldOutlined />
                  ) : (
                    <MenuFoldOutlined />
                  )
                }
                onClick={() =>
                  setPreferences((previous) => ({
                    ...previous,
                    collapsed: !previous.collapsed,
                  }))
                }
              />
            </Tooltip>
          </nav>
          <div
            className="context-menu-panel"
            aria-hidden={preferences.collapsed}
            ref={(element) => {
              if (element) element.inert = preferences.collapsed;
            }}
          >
            <ContextMenu key={current?.product.id} />
          </div>
        </aside>
      </div>
      <Drawer
        destroyOnHidden
        title={current?.product.name ?? '功能菜单'}
        placement="left"
        size={300}
        open={mobileOpen}
        onClose={() => setMobileOpen(false)}
        styles={{ body: { padding: '16px 0 0' } }}
      >
        <ContextMenu showHeading={false} key={current?.product.id} />
      </Drawer>
    </ConfigProvider>
  );
}
