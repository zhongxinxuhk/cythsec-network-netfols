// Ant Design Pro 路由真源：菜单、面包屑和页面路由由 Umi 统一生成。
export interface ConsoleRoute {
  path: string;
  name?: string;
  icon?: string;
  component?: string;
  redirect?: string;
  layout?: boolean;
  routes?: ConsoleRoute[];
}
const businessRoutes: ConsoleRoute[] = [
  { path: '/', name: '运行概览', icon: 'DashboardOutlined', component: './DashboardPage' },
  { path: '/interfaces', name: '网络接口', icon: 'ClusterOutlined', component: './InterfacesPage' },
  { path: '/routes', name: '路由表', icon: 'BranchesOutlined', component: './RoutesPage' },
  { path: '/traffic', name: '接口流量', icon: 'AreaChartOutlined', component: './TrafficPage' },
  { path: '/analytics', name: '聚合分析', icon: 'BarChartOutlined', component: './AnalyticsPage' },
  { path: '/system', name: '系统信息', icon: 'SettingOutlined', component: './SystemPage' },
];

export function createConsoleRoutes(includeDesign: boolean): ConsoleRoute[] {
  return [
    ...businessRoutes,
    ...(includeDesign ? [{
      path: '/design', name: '设计工作区', icon: 'ExperimentOutlined',
      routes: [
        { path: '/design', redirect: '/design/overview' },
        { path: '/design/overview', name: '运行概览', component: '@/design/DesignWorkspacePage' },
        { path: '/design/topology', name: '网络拓扑', component: '@/design/DesignWorkspacePage' },
        { path: '/design/asset', name: '资产技术画像', component: '@/design/DesignWorkspacePage' },
        { path: '/design/integrations', name: '安全设备联动', component: '@/design/DesignWorkspacePage' },
        { path: '/design/incident', name: '事件调查', component: '@/design/DesignWorkspacePage' },
      ],
    }] : []),
    { path: '*', component: './NotFoundPage', layout: false },
  ];
}

// Fixtures never enter the production route graph or its asynchronously built pages.
export default createConsoleRoutes(process.env.NODE_ENV === 'development');
