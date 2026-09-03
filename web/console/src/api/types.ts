// types.ts - 与 routerd /api/v1 返回结构对应的前端类型。

// routerd 统一 JSON 包装 { data: ... }
export interface ApiEnvelope<T> {
  data: T;
  error?: string;
}

// /api/v1/system
export interface SystemInfo {
  hostname: string;
  os: string;
  arch: string;
  go_version: string;
  pid: number;
}

// 网卡上的一个地址
export interface InterfaceAddr {
  ip: string;
  cidr: string;
  scope?: string;
  is_loopback: boolean;
}

// /api/v1/interfaces 里的一张网卡
export interface InterfaceInfo {
  name: string;
  index: number;
  mtu: number;
  mac: string;
  flags: string[];
  up: boolean;
  running: boolean;
  loopback: boolean;
  broadcast: boolean;
  multicast: boolean;
  point_to_point: boolean;
  addresses: InterfaceAddr[];
}

// /api/v1/routes 里的一条路由
export interface Route {
  interface: string;
  destination: string;
  gateway: string;
  mask: string;
  flags: string;
  metric: number;
  ref: number;
  use: number;
}
