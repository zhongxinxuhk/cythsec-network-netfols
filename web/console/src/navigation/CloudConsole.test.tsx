import { beforeEach, expect, it, vi } from 'vitest';
import { render } from 'vitest-browser-react';
import { MemoryRouter, useLocation } from 'react-router-dom';

vi.mock('@umijs/max', async () => {
  const router = await import('react-router-dom');
  return {
    Link: router.Link,
    useLocation: router.useLocation,
    useAccess: () => ({ canAdmin: true }),
  };
});
import { CloudHeader, CloudNavigation } from './CloudConsole';
import { NavigationProvider } from './NavigationProvider';

function Location() {
  return <output aria-label="当前路径">{useLocation().pathname}</output>;
}
function Console() {
  return (
    <MemoryRouter initialEntries={['/dashboard/analysis']}>
      <NavigationProvider>
        <CloudHeader />
        <CloudNavigation />
        <Location />
      </NavigationProvider>
    </MemoryRouter>
  );
}
beforeEach(() => localStorage.clear());
it('catalog searches, favorites and navigates through the same router', async () => {
  const screen = await render(<Console />);
  await screen.getByRole('button', { name: '打开产品与服务' }).click();
  await screen.getByRole('textbox', { name: '搜索全部功能' }).fill('路由表');
  await screen
    .getByRole('button', { name: '收藏网络与流量 · 路由表', exact: true })
    .click();
  await expect
    .element(
      screen.getByRole('button', {
        name: '取消收藏网络与流量 · 路由表',
        exact: true,
      }),
    )
    .toBeVisible();
  await screen.getByRole('tab', { name: '我的收藏', exact: true }).click();
  await screen.getByRole('link', { name: '路由表', exact: true }).click();
  await expect
    .element(screen.getByLabelText('当前路径'))
    .toHaveTextContent('/network/routes');
  await expect.element(screen.getByRole('dialog')).not.toBeInTheDocument();
});
it('collapsing the context menu preserves the module rail and can be restored', async () => {
  localStorage.setItem('cythsec.console.navigation.v1', '{broken');
  const screen = await render(<Console />);
  await expect
    .element(screen.getByRole('navigation', { name: '仪表盘功能菜单' }))
    .toBeVisible();
  await screen.getByRole('button', { name: '收起功能菜单' }).click();
  await expect
    .element(screen.getByRole('button', { name: '展开功能菜单' }))
    .toHaveAttribute('aria-expanded', 'false');
  await screen.getByRole('button', { name: '展开功能菜单' }).click();
  await expect
    .element(screen.getByRole('navigation', { name: '仪表盘功能菜单' }))
    .toBeVisible();
});
