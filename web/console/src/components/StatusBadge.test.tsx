import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { StatusBadge } from './StatusBadge';
afterEach(cleanup);
describe('Ant Design 状态语义', () => {
  it.each([['ok', 'success'], ['err', 'error'], ['warn', 'warning'], ['muted', 'default']] as const)('%s 使用 %s 状态且保留文本', (tone, status) => {
    const { container } = render(<StatusBadge tone={tone} label={`service-${tone}`} />);
    expect(screen.getByText(`service-${tone}`)).toBeInTheDocument();
    expect(container.querySelector(`.ant-badge-status-${status}`)).not.toBeNull();
  });
});
