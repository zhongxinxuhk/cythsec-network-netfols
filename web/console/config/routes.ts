// Ant Design Pro 路由真源：菜单、面包屑和页面路由由 Umi 统一生成。
export interface ConsoleProduct {
  id: string;
  name: string;
  icon: string;
}
export interface ConsoleRoute {
  consoleProduct?: ConsoleProduct;
  consoleSection?: string;
  path: string;
  name?: string;
  icon?: string;
  component?: string;
  redirect?: string;
  layout?: boolean;
  routes?: ConsoleRoute[];
}
const workspace = { id: 'workspace', name: '工作台', icon: 'DashboardOutlined' };
const network = { id: 'network', name: '网络管理', icon: 'ClusterOutlined' };
const analytics = { id: 'analytics', name: '流量分析', icon: 'BarChartOutlined' };
const data = { id: 'data', name: '数据管理', icon: 'DatabaseOutlined' };
const platform = { id: 'platform', name: '平台管理', icon: 'SettingOutlined' };
const design = { id: 'design', name: '设计工作区', icon: 'ExperimentOutlined' };
const businessRoutes: ConsoleRoute[] = [
  { consoleProduct: workspace, consoleSection: '运行监测', path: '/', name: '运行概览', icon: 'DashboardOutlined', component: './DashboardPage' },
  { consoleProduct: network, consoleSection: '网络资源', path: '/interfaces', name: '网络接口', icon: 'ClusterOutlined', component: './InterfacesPage' },
  { consoleProduct: network, consoleSection: '网络资源', path: '/routes', name: '路由表', icon: 'BranchesOutlined', component: './RoutesPage' },
  { consoleProduct: network, consoleSection: '运行监测', path: '/traffic', name: '接口流量', icon: 'AreaChartOutlined', component: './TrafficPage' },
  { consoleProduct: network, consoleSection: '网络配置', path: '/network/configuration', name: '网络配置', icon: 'SettingOutlined', component: './NetworkConfigurationPage' },
  { consoleProduct: analytics, consoleSection: '聚合数据', path: '/analytics', name: '聚合分析', icon: 'BarChartOutlined', component: './AnalyticsPage' },
  { consoleProduct: analytics, consoleSection: '指标口径', path: '/analytics/metrics', name: '指标字典', icon: 'BookOutlined', component: './MetricDictionaryPage' },
  { consoleProduct: data, consoleSection: '写入管道', path: '/data/queue', name: '写入队列', icon: 'DatabaseOutlined', component: './IngestQueuePage' },
  { consoleProduct: platform, consoleSection: '系统管理', path: '/system', name: '系统信息', icon: 'SettingOutlined', component: './SystemPage' },
];

export function createConsoleRoutes(includeDesign: boolean): ConsoleRoute[] {
  return [
    ...businessRoutes,
    ...(includeDesign ? [{
      consoleProduct: design, path: '/design', name: '设计工作区', icon: 'ExperimentOutlined',
      routes: [
        { path: '/design', redirect: '/design/overview' },
        { consoleSection: '运行视图', path: '/design/overview', name: '运行概览', component: '@/design/DesignWorkspacePage' },
        { consoleSection: '网络资产', path: '/design/topology', name: '网络拓扑', component: '@/design/DesignWorkspacePage' },
        { consoleSection: '网络资产', path: '/design/asset', name: '资产技术画像', component: '@/design/DesignWorkspacePage' },
        { consoleSection: '安全协作', path: '/design/integrations', name: '安全设备联动', component: '@/design/DesignWorkspacePage' },
        { consoleSection: '安全协作', path: '/design/incident', name: '事件调查', component: '@/design/DesignWorkspacePage' },
      ],
    }] : []),
    { path: '*', component: './NotFoundPage', layout: false },
  ];
}

// Fixtures never enter the production route graph or its asynchronously built pages.
export default createConsoleRoutes(process.env.NODE_ENV === 'development');
