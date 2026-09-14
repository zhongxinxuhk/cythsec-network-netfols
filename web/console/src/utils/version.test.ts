// version.test.ts - 版本号读取出口的测试。
//
// 这组用例的价值不在「函数返回字符串」这种显然的事，而在于**证明注入链路
// 是通的**：__APP_VERSION__ 由构建期从仓库根 VERSION 注入，若某天有人把
// define 配置删掉，这些用例会立刻失败 —— 而界面只是安静地显示无版本号，
// 那种退化很难被人注意到。
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { appVersion, isSemver, versionLabel } from './version';

describe('appVersion', () => {
  it('返回非空字符串', () => {
    expect(typeof appVersion()).toBe('string');
    expect(appVersion().length).toBeGreaterThan(0);
  });

  it('取得的版本号等于仓库根 VERSION 的内容', () => {
    // 直接从真源读取比对，而非比对某个写死的期望值 ——
    // 写死期望值会在 VERSION 更新时变成需要同步的又一份副本。
    const truth = readFileSync(resolve(__dirname, '../../../../VERSION'), 'utf-8').trim();
    expect(appVersion()).toBe(truth);
  });

  it('是合法 semver', () => {
    expect(isSemver(appVersion())).toBe(true);
  });
});

describe('versionLabel', () => {
  it('带 v 前缀', () => {
    expect(versionLabel()).toBe(`v${appVersion()}`);
    expect(versionLabel().startsWith('v')).toBe(true);
  });
});

describe('isSemver', () => {
  it('接受标准三段式', () => {
    expect(isSemver('0.1.0')).toBe(true);
    expect(isSemver('12.34.56')).toBe(true);
  });

  it('接受预发布与构建后缀', () => {
    expect(isSemver('1.0.0-alpha.1')).toBe(true);
    expect(isSemver('1.0.0+build.7')).toBe(true);
  });

  it('拒绝非 semver 形态', () => {
    expect(isSemver('dev')).toBe(false);
    expect(isSemver('1.0')).toBe(false);
    expect(isSemver('v1.0.0')).toBe(false);
    expect(isSemver('')).toBe(false);
  });
});
