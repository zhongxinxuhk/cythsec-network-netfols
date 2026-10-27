import { useState } from 'react';
import { Button } from 'antd';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';

// Isolate the Umi adapter, keeping the real router and Ant/Pro components.
vi.mock('@umijs/max', async () => {
  const router = await import('react-router-dom');
  return { Link: router.Link, useLocation: router.useLocation };
});
import DesignWorkspacePage from './DesignWorkspacePage';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('设计内部链接走主路由且保留父级状态，不请求管理接口或创建另一套菜单', () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  function SharedShell() {
    const [count, setCount] = useState(0);
    return <><Button onClick={() => setCount(count + 1)}>父级状态 {count}</Button><DesignWorkspacePage /></>;
  }
  render(<MemoryRouter initialEntries={['/design/overview']}><SharedShell /></MemoryRouter>);
  fireEvent.click(screen.getByRole('button', { name: '父级状态 0' }));
  fireEvent.click(screen.getByRole('link', { name: '打开拓扑' }));
  expect(screen.getByText('物理关系与容量')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: '父级状态 1' })).toBeInTheDocument();
  expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  expect(fetch).not.toHaveBeenCalled();
}, 15000);

it('未接入事件后台时确认操作禁用，不产生本地伪成功', () => {
  render(<MemoryRouter initialEntries={['/design/incident']}><DesignWorkspacePage /></MemoryRouter>);
  expect(screen.getByRole('button', { name: '确认事件' })).toBeDisabled();
});
