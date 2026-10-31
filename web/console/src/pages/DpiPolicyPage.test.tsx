import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { dpiPolicy } from '@/api/dpi';
import type { DpiModule, DpiPolicy, DpiState } from '@/api/dpi';
import { ApiError } from '@/api/http';
import { DpiPolicyPage } from './DpiPolicyPage';

vi.mock('@/api/dpi', () => ({ dpiPolicy: { read: vi.fn(), modules: vi.fn(), save: vi.fn() } }));

const modules: DpiModule[] = [
  { key: 'tls', name: 'TLS ClientHello', group: '应用与名称解析', availability: 'implemented', catalog_ids: ['T001', 'T002', 'T022'], default_enabled: true },
  { key: 'smtp', name: 'SMTP', group: '应用与名称解析', availability: 'implemented', catalog_ids: ['B020'], default_enabled: true },
  { key: 'vxlan', name: 'VXLAN', group: '隧道与代理（结构候选）', availability: 'candidate', catalog_ids: ['V014'], default_enabled: true },
];

const policy: DpiPolicy = {
  schema_version: 1,
  enabled: true,
  intensity: 'standard',
  inspect_bytes: null,
  modules: { tls: true, smtp: true, vxlan: true },
  tls_decrypt: { enabled: false, keylog_file: '' },
};
const state: DpiState = { snapshot: { revision: 4, updated_at: '2026-10-31T00:00:00Z', policy }, capabilities: { can_save: true, store_enabled: true } };

beforeEach(() => {
  vi.mocked(dpiPolicy.modules).mockResolvedValue({ schema_version: 1, modules });
  vi.mocked(dpiPolicy.read).mockResolvedValue(state);
  vi.mocked(dpiPolicy.save).mockImplementation(async (next, revision) => ({ revision: revision + 1, updated_at: '2026-10-31T01:00:00Z', policy: next }));
});
afterEach(() => { cleanup(); vi.resetAllMocks(); });

describe('DPI 策略', () => {
  it('逐协议开关会进入保存请求并带版本号', async () => {
    render(<DpiPolicyPage />);
    expect(await screen.findByText('TLS ClientHello')).toBeInTheDocument();
    expect(screen.getByText('结构候选')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('switch', { name: 'SMTP 模块开关' }));
    expect(screen.getByText('有未保存的修改')).toBeInTheDocument();
    fireEvent.click(screen.getByText('保存策略'));
    await waitFor(() => expect(dpiPolicy.save).toHaveBeenCalledWith(
      expect.objectContaining({ modules: expect.objectContaining({ smtp: false }) }),
      4,
    ));
    expect(await screen.findByText(/策略已保存为版本 5/)).toBeInTheDocument();
  });

  it('只读身份明确提示且不能保存', async () => {
    vi.mocked(dpiPolicy.read).mockResolvedValue({ ...state, capabilities: { can_save: false, store_enabled: true } });
    render(<DpiPolicyPage />);
    expect(await screen.findByText('当前身份为只读')).toBeInTheDocument();
    expect(screen.getByText('保存策略').closest('button')).toBeDisabled();
  });

  it('版本冲突不伪装成保存成功', async () => {
    vi.mocked(dpiPolicy.save).mockRejectedValueOnce(new ApiError('策略版本已变化，请重新读取后再保存', 412));
    render(<DpiPolicyPage />);
    await screen.findByText('TLS ClientHello');
    fireEvent.click(screen.getByRole('switch', { name: 'SMTP 模块开关' }));
    fireEvent.click(screen.getByText('保存策略'));
    expect(await screen.findByRole('alert')).toHaveTextContent('策略版本已变化');
  });

  it('启用 TLS 解密但缺少密钥路径时拒绝保存', async () => {
    render(<DpiPolicyPage />);
    await screen.findByText('TLS ClientHello');
    fireEvent.click(screen.getByRole('switch', { name: 'TLS 解密开关' }));
    fireEvent.click(screen.getByText('保存策略'));
    expect(await screen.findByRole('alert')).toHaveTextContent('必须填写运维方提供的 key log 绝对路径');
    expect(dpiPolicy.save).not.toHaveBeenCalled();
  });
});
