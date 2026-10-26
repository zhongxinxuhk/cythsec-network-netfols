import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { App } from './App';

// 保留真实 Router、Layout 与导航，只隔离页面的数据请求。
vi.mock('@/pages/DashboardPage', () => ({ DashboardPage: () => <h1>Dashboard content</h1> }));
vi.mock('@/pages/InterfacesPage', () => ({ InterfacesPage: () => <h1>Interfaces content</h1> }));
vi.mock('@/pages/RoutesPage', () => ({ RoutesPage: () => <h1>Routes content</h1> }));
vi.mock('@/pages/TrafficPage', () => ({ TrafficPage: () => <h1>Traffic content</h1> }));
vi.mock('@/pages/AnalyticsPage', () => ({ AnalyticsPage: () => <h1>聚合分析 content</h1> }));
vi.mock('@/pages/SystemPage', () => ({ SystemPage: () => <h1>System content</h1> }));

describe('Router 升级后的正常导航契约', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it.each([
    ['/', 'Dashboard'],
    ['/interfaces', 'Interfaces'],
    ['/routes', 'Routes'],
    ['/traffic', 'Traffic'],
    ['/system', 'System'],
    ['/analytics', '聚合分析'],
  ])('直接打开 %s 时展示对应页面并仅高亮当前导航', async (path, name) => {
    window.history.replaceState({}, '', path);
    const { container } = render(<App />);
    expect(screen.getByRole('heading', { name: `${name} content` })).toBeInTheDocument();
    expect(screen.getByRole('link', { name })).toHaveClass('nav-link', 'active');
    expect(container.querySelectorAll('.nav-link.active')).toHaveLength(1);
    expect(await screen.findByText('routerd online')).toBeInTheDocument();
  });

  it('点击内部导航时保留真实客户端路由与 active 状态', async () => {
    render(<App />);
    fireEvent.click(screen.getByRole('link', { name: 'Traffic' }));
    expect(await screen.findByRole('heading', { name: 'Traffic content' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/traffic');
    expect(screen.getByRole('link', { name: 'Traffic' })).toHaveClass('active');
    expect(screen.getByRole('link', { name: 'Dashboard' })).not.toHaveClass('active');
    expect(await screen.findByText('routerd online')).toBeInTheDocument();
  });

  it('未知路径仍替换重定向回首页', async () => {
    window.history.replaceState({}, '', '/unknown-route');
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Dashboard content' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/');
    expect(await screen.findByText('routerd online')).toBeInTheDocument();
  });
});
