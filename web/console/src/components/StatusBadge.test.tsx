// StatusBadge.test.tsx - 状态徽标组件的渲染测试。
// 徽标是顶栏 "routerd online / offline" 的唯一可视化落点，tone 到 CSS 类的映射错了
// 会让运维把「服务已挂」误读成「正常」，因此四种 tone 的映射必须逐个锁死。
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { StatusBadge } from './StatusBadge';

describe('StatusBadge', () => {
  it('渲染传入的文本标签', () => {
    render(<StatusBadge tone="ok" label="routerd online" />);
    expect(screen.getByText('routerd online')).toBeInTheDocument();
  });

  it.each([
    ['ok', 'badge-ok'],
    ['err', 'badge-err'],
    ['warn', 'badge-warn'],
    ['muted', 'badge-muted'],
  ] as const)('tone=%s 映射到 CSS 类 %s', (tone, expectedClass) => {
    render(<StatusBadge tone={tone} label={`tone-${tone}`} />);
    const el = screen.getByText(`tone-${tone}`);
    expect(el).toHaveClass('status-badge', expectedClass);
  });

  it('始终渲染状态指示圆点，且圆点与文本同属一个容器', () => {
    const { container } = render(<StatusBadge tone="muted" label="…" />);
    const badge = container.querySelector('.status-badge');
    expect(badge).not.toBeNull();
    expect(badge?.querySelector('.dot')).not.toBeNull();
  });
});
