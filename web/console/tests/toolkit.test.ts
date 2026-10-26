import { ReloadOutlined, UploadOutlined } from '@ant-design/icons';
import { expect, it } from 'vitest';
import { PageContainer, ProCard, ProDescriptions, ProTable } from '@ant-design/pro-components';
import { Alert, Button, Collapse, DatePicker, Empty, Form, Progress, Select, Space, Typography, Upload } from 'antd';
it('生产使用的 Pro 与 Ant Design 导出均可解析', () => {
  for (const [name, component] of Object.entries({ PageContainer, ProCard, ProDescriptions, ProTable, Alert, Button, Collapse, DatePicker, Empty, Form, Progress, Select, Space, Typography, Paragraph: Typography.Paragraph, FormItem: Form.Item, Upload, ReloadOutlined, UploadOutlined })) expect(component, name).toBeDefined();
});
