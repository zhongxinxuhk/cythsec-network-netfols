import { useState } from 'react';
import { PageContainer, ProCard, ProDescriptions, ProTable, type ProColumns } from '@ant-design/pro-components';
import { Button, Empty, Input, Tag, Tree, Typography } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import { aggregateMetrics, type MetricDefinition } from '@/constants/aggregate-metrics';
import './metric-dictionary.css';

export default function MetricDictionaryPage() {
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(aggregateMetrics[0].field);
  const normalized = query.trim().toLocaleLowerCase();
  const filtered = aggregateMetrics.filter(metric => `${metric.name} ${metric.field} ${metric.group}`.toLocaleLowerCase().includes(normalized));
  const current = filtered.find(metric => metric.field === selected) ?? filtered[0];
  const groups = Array.from(new Set(filtered.map(metric => metric.group)));
  const columns: ProColumns<MetricDefinition>[] = [
    { title: '指标', dataIndex: 'name', width: 190, render: (_, metric) => <Button type="link" onClick={() => setSelected(metric.field)}>{metric.name}</Button> },
    { title: '字段路径', dataIndex: 'field', width: 390, copyable: true },
    { title: '单位', dataIndex: 'unit', width: 100 },
    { title: '叶值可空', dataIndex: 'nullable', width: 100, render: (_, metric) => metric.nullable ? '是' : '否' },
  ];
  return <PageContainer content="聚合查询字段、单位与统计口径"><div className="metric-dictionary-layout">
    <ProCard title="指标目录" variant="outlined">
      <Input prefix={<SearchOutlined />} allowClear aria-label="搜索指标" placeholder="名称、字段、分类" value={query} onChange={event => setQuery(event.target.value)} />
      <nav className="metric-dictionary-tree" aria-label="指标分类">
        {filtered.length ? <Tree key={query} blockNode defaultExpandAll selectedKeys={current ? [current.field] : []}
          onSelect={keys => { const metric = filtered.find(item => item.field === keys[0]); if (metric) setSelected(metric.field); }}
          treeData={groups.map(group => ({ key: group, title: group, selectable: false, children: filtered.filter(metric => metric.group === group).map(metric => ({ key: metric.field, title: metric.name })) }))} /> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有匹配的指标" />}
      </nav>
    </ProCard>
    <div className="page-stack metric-dictionary-detail">
      <ProCard title={current?.name ?? '指标详情'} variant="outlined">
        {current ? <ProDescriptions<MetricDefinition> dataSource={current} column={1} columns={[
          { title: '字段路径', dataIndex: 'field', copyable: true },
          { title: '分类', dataIndex: 'group', render: (_, metric) => <Tag>{metric.group}</Tag> },
          { title: '单位', dataIndex: 'unit' },
          { title: '统计定义', dataIndex: 'definition' },
          { title: '发布条件', dataIndex: 'availability' },
          { title: '叶值可空', dataIndex: 'nullable', render: (_, metric) => metric.nullable ? '是；未发布时保留空值' : metric.field.startsWith('statistics.') ? '否；父对象仍可能因抑制而未发布' : '否' },
          { title: '显示限制', dataIndex: 'limits' },
          { title: '契约来源', render: () => '聚合窗口与批次状态查询投影' },
        ]} /> : <Empty description="没有匹配的指标" />}
        <Typography.Paragraph type="secondary">字段为空、父级未发布与实际零值分别显示。窗口统计按批次独立查询。</Typography.Paragraph>
      </ProCard>
      <ProTable<MetricDefinition> headerTitle={`字段清单 · ${filtered.length} 项`} rowKey="field" columns={columns} dataSource={filtered}
        search={false} options={false} scroll={{ x: 780 }} pagination={{ pageSize: 10, showSizeChanger: false }} locale={{ emptyText: '没有匹配的指标' }} />
    </div>
  </div></PageContainer>;
}
