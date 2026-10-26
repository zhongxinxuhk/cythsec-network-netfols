// Ant Design Pro 路由真源：菜单、面包屑和页面路由由 Umi 统一生成。
export default [
  { path: '/', name: '运行概览', icon: 'DashboardOutlined', component: './DashboardPage' },
  { path: '/interfaces', name: '网络接口', icon: 'ClusterOutlined', component: './InterfacesPage' },
  { path: '/routes', name: '路由表', icon: 'BranchesOutlined', component: './RoutesPage' },
  { path: '/traffic', name: '接口流量', icon: 'AreaChartOutlined', component: './TrafficPage' },
  { path: '/analytics', name: '聚合分析', icon: 'BarChartOutlined', component: './AnalyticsPage' },
  { path: '/system', name: '系统信息', icon: 'SettingOutlined', component: './SystemPage' },
  { path: '*', component: './NotFoundPage', layout: false },
];
