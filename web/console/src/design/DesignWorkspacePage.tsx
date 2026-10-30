import { useLocation } from '@umijs/max';
import { Result } from 'antd';
import ConsoleDesign, { type DesignView } from './ConsoleDesign';

export default function DesignWorkspacePage() {
  const { pathname } = useLocation();
  const view = pathname.slice('/design/'.length);
  if (!['overview', 'topology', 'asset', 'integrations', 'incident'].includes(view)) {
    return <Result status="404" title="页面不存在" />;
  }
  return <ConsoleDesign key={pathname} page={view as DesignView} />;
}
