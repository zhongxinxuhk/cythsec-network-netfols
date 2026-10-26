import { Button, Result } from 'antd';
import { history } from '@umijs/max';
export default function NotFoundPage() {
  return <Result status="404" title="404" subTitle="页面不存在" extra={<Button type="primary" onClick={() => history.push('/')}>返回运行概览</Button>} />;
}
