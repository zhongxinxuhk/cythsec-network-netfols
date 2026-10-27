import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
vi.mock('@umijs/max', async () => {
  const router = await import('react-router-dom');
  return { Link: router.Link, useLocation: router.useLocation };
});
// Health/access are covered independently; keep real router and Ant navigation controls.
vi.mock('@/components/HeaderStatus', () => ({ HeaderStatus: () => <span>服务状态</span> }));
vi.mock('@/components/ServiceAccess', () => ({ ServiceAccess: () => <span>服务认证</span> }));
import { CloudHeader, CloudNavigation } from './CloudConsole';
import { NavigationProvider } from './NavigationProvider';
function Location() { return <output aria-label="当前路径">{useLocation().pathname}</output>; }
function mount(path = '/interfaces') {
  return render(<MemoryRouter initialEntries={[path]}><NavigationProvider><CloudHeader /><CloudNavigation /><Location /></NavigationProvider></MemoryRouter>);
}
beforeEach(() => localStorage.clear());
afterEach(cleanup);

it('分类目录可搜索、收藏、移除收藏并通过同一SPA导航，最近访问跟随真实路径', async () => {
  mount();
  fireEvent.click(screen.getByRole('button', { name: '打开产品与服务' }));
  const dialog = await screen.findByRole('dialog', { name: '产品与服务' });
  const search = within(dialog).getByRole('textbox', { name: '搜索全部功能' });
  fireEvent.change(search, { target: { value: '聚合分析' } });
  expect(within(dialog).queryByRole('link', { name: '路由表' })).not.toBeInTheDocument();
  fireEvent.click(within(dialog).getByRole('button', { name: '收藏流量分析 · 聚合分析' }));
  expect(within(dialog).getByRole('button', { name: '取消收藏流量分析 · 聚合分析' })).toHaveAttribute('aria-pressed', 'true');
  fireEvent.click(within(dialog).getByRole('tab', { name: '我的收藏' }));
  fireEvent.click(within(dialog).getByRole('link', { name: '聚合分析' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(screen.getByLabelText('当前路径')).toHaveTextContent('/analytics');
  expect(screen.getByRole('navigation', { name: '流量分析功能菜单' })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: '打开产品与服务' }));
  fireEvent.click(screen.getByRole('tab', { name: '最近访问' }));
  expect(screen.getByRole('dialog')).toHaveTextContent('聚合分析');
  fireEvent.click(screen.getByRole('tab', { name: '我的收藏' }));
  fireEvent.click(screen.getByRole('button', { name: '取消收藏流量分析 · 聚合分析' }));
  expect(screen.getByRole('dialog')).toHaveTextContent('暂无收藏');
}, 15000);

it('侧栏分组独立收纳、筛选和收起；损坏存储不妨碍导航', async () => {
  localStorage.setItem('cythsec.console.navigation.v1', '{broken');
  mount();
  const menu = screen.getByRole('navigation', { name: '网络管理功能菜单' });
  fireEvent.click(within(menu).getByRole('menuitem', { name: '网络资源' }));
  await waitFor(() => expect(within(menu).queryByRole('link', { name: '路由表' })).not.toBeInTheDocument());
  fireEvent.click(within(menu).getByRole('menuitem', { name: '网络资源' }));
  fireEvent.change(screen.getByRole('textbox', { name: '搜索当前模块' }), { target: { value: '路由' } });
  expect(within(menu).getByRole('link', { name: '路由表' })).toBeInTheDocument();
  expect(within(menu).queryByRole('link', { name: '网络接口' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: '收起功能菜单' }));
  expect(screen.queryByRole('navigation', { name: '网络管理功能菜单' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: '展开功能菜单' })).toHaveAttribute('aria-expanded', 'false');
  fireEvent.click(screen.getByRole('button', { name: '展开功能菜单' }));
  fireEvent.click(within(menu).getByRole('link', { name: '路由表' }));
  expect(screen.getByLabelText('当前路径')).toHaveTextContent('/routes');
}, 15000);

it('窄屏功能抽屉沿用当前模块，切换后关闭，Esc关闭目录', async () => {
  mount('/routes');
  fireEvent.click(screen.getByRole('button', { name: '打开当前模块菜单' }));
  const drawer = await screen.findByRole('dialog', { name: '网络管理' });
  fireEvent.click(within(drawer).getByRole('link', { name: '接口流量' }));
  await waitFor(() => expect(drawer).not.toBeInTheDocument());
  expect(screen.getByLabelText('当前路径')).toHaveTextContent('/traffic');
  fireEvent.click(screen.getByRole('button', { name: '打开产品与服务' }));
  const catalog = await screen.findByRole('dialog', { name: '产品与服务' });
  fireEvent.keyDown(catalog, { key: 'Escape', keyCode: 27 });
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
}, 15000);
