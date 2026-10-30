import '@testing-library/jest-dom/vitest';
// jsdom 不实现布局和媒体查询；组件本身保持真实 Ant Design / Pro 实现。
Object.defineProperty(window, 'matchMedia', { writable: true, value: (query: string) => ({ matches: false, media: query, onchange: null, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return false; } }) });
globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
const originalGetComputedStyle = window.getComputedStyle;
window.getComputedStyle = (element) => originalGetComputedStyle(element);
window.scrollTo = () => {};
HTMLElement.prototype.scrollTo = () => {};
