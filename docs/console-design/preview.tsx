import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Alert,
  App,
  Button,
  ConfigProvider,
  Descriptions,
  Drawer,
  Empty,
  Grid,
  List,
  Radio,
  Select,
  Space,
  Statistic,
  Steps,
  Switch,
  Table,
  Tabs,
  Tag,
  Timeline,
  Typography,
  theme,
} from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  ProCard,
  ProLayout,
  PageContainer,
  ProTable,
} from "@ant-design/pro-components";
import {
  ApartmentOutlined,
  ApiOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  DeploymentUnitOutlined,
  SafetyCertificateOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  WarningOutlined,
  InfoCircleOutlined,
} from "@ant-design/icons";
import "./preview.css";

const { Text, Paragraph, Title } = Typography;
type Page = "overview" | "topology" | "asset" | "integrations" | "incident";
const navigation = [
  { path: "/overview", name: "运行概览", icon: <DashboardOutlined /> },
  { path: "/topology", name: "网络拓扑", icon: <ApartmentOutlined /> },
  { path: "/asset", name: "资产技术画像", icon: <DatabaseOutlined /> },
  { path: "/integrations", name: "安全设备联动", icon: <ApiOutlined /> },
  {
    path: "/incident",
    name: "安全事件调查",
    icon: <SafetyCertificateOutlined />,
  },
];
const titles: Record<Page, [string, string]> = {
  overview: ["网络运行概览", "链路、受管资产与安全设备的统一观测视图"],
  topology: [
    "受管基础设施拓扑",
    "关系来自合成库存证据；通信关系与物理链路分层展示",
  ],
  asset: ["CORE-GW-01", "受管网关技术档案 · 地址关联、接口质量与事件证据"],
  integrations: [
    "安全设备联动",
    "传输、解析与业务核对分别展示，任务结果保留未知状态",
  ],
  incident: [
    "接口丢弃计数持续上升",
    "合成事件 SEC-DEMO-027 · 受管核心网关 · 运行质量异常",
  ],
};
const assetRows = [
  {
    key: "gw",
    name: "CORE-GW-01",
    type: "核心网关",
    ip: "192.0.2.1",
    state: "已核实",
    zone: "核心区",
    source: "目录 + 只读接口",
  },
  {
    key: "sw",
    name: "AGG-SW-02",
    type: "汇聚交换机",
    ip: "192.0.2.2",
    state: "已核实",
    zone: "汇聚区",
    source: "目录 + 邻居表",
  },
  {
    key: "fw",
    name: "SEC-FW-01",
    type: "安全设备",
    ip: "198.51.100.10",
    state: "待核实",
    zone: "服务区",
    source: "目录声明",
  },
];
const connectors = [
  {
    key: "c1",
    name: "边界安全设备",
    adapter: "合成 NGFW 适配器",
    transport: "正常",
    parse: "正常",
    verify: "未执行",
    events: "48",
    delay: "0.8 s",
  },
  {
    key: "c2",
    name: "网络入侵检测",
    adapter: "合成 IDS 适配器",
    transport: "正常",
    parse: "异常",
    verify: "不适用",
    events: "12",
    delay: "未知",
  },
  {
    key: "c3",
    name: "资产目录",
    adapter: "合成 CMDB 适配器",
    transport: "正常",
    parse: "正常",
    verify: "已核对",
    events: "3",
    delay: "1.2 s",
  },
];

function Status({ value }: { value: string }) {
  const good = ["正常", "已核实", "已核对", "已验证"].includes(value);
  const bad = ["异常", "失败"].includes(value);
  const pending = ["待核实", "结果未知"].includes(value);
  return (
    <Tag
      color={good ? "success" : bad ? "error" : pending ? "warning" : "default"}
      icon={
        good ? (
          <CheckCircleOutlined />
        ) : bad ? (
          <WarningOutlined />
        ) : (
          <ClockCircleOutlined />
        )
      }
    >
      {value}
    </Tag>
  );
}

function Metrics({
  items,
}: {
  items: [string, string | number, string, string][];
}) {
  return (
    <div className="design-stats">
      {items.map(([title, value, unit, note]) => (
        <ProCard key={title} variant="outlined">
          <Statistic
            title={title}
            value={value}
            suffix={<Text type="secondary">{unit}</Text>}
          />
          <Text type="secondary">{note}</Text>
        </ProCard>
      ))}
    </div>
  );
}

function Trend({ quality = false }: { quality?: boolean }) {
  const { token } = theme.useToken();
  const lines = quality
    ? [
        [60, 62, 54, 57, 53, 61, 81, 91, 74, 69, 60, 63],
        [24, 25, 28, 26, 24, 31, 37, 39, 35, 29, 28, 26],
      ]
    : [
        [6.5, 7.3, 6.7, 9.5, 8.9, 8.3, 10.8, 12.2, 11.4, 13, 11.9, 11.3],
        [3.5, 4.1, 3.7, 5.2, 4.9, 4.6, 6.1, 7, 6, 7.5, 7, 6.5],
      ];
  const points = (values: number[]) =>
    values
      .map(
        (v, i) => `${58 + i * (516 / 11)},${208 - v * (quality ? 1.05 : 10.5)}`,
      )
      .join(" ");
  return (
    <>
      <svg
        viewBox="0 0 620 260"
        className="design-chart"
        role="img"
        aria-label={
          quality
            ? "合成RTT分位趋势，中段p95上升，数据替代见下方文字"
            : "合成接口收发趋势，数据替代见下方文字"
        }
      >
        {[0, 1, 2, 3, 4].map((i) => (
          <g key={i}>
            <line
              x1="58"
              x2="590"
              y1={208 - i * 42}
              y2={208 - i * 42}
              stroke={token.colorBorderSecondary}
            />
            <text
              x="44"
              y={212 - i * 42}
              textAnchor="end"
              fill={token.colorTextSecondary}
              fontSize="12"
            >
              {i * (quality ? 40 : 4)}
            </text>
          </g>
        ))}
        <text x="20" y="22" fill={token.colorTextSecondary} fontSize="12">
          {quality ? "ms" : "Gbps"}
        </text>
        <polyline
          points={points(lines[0])}
          stroke={token.colorPrimary}
          strokeWidth="2.5"
          fill="none"
        />
        <polyline
          points={points(lines[1])}
          stroke="#13a8a8"
          strokeWidth="2.5"
          fill="none"
        />
        {["09:00", "09:15", "09:30", "09:45", "10:00"].map((v, i) => (
          <text
            key={v}
            x={58 + i * 129}
            y="239"
            textAnchor="middle"
            fill={token.colorTextSecondary}
            fontSize="12"
          >
            {v}
          </text>
        ))}
      </svg>
      <div className="design-legend">
        <Text>
          <Tag color="blue">{quality ? "p95" : "接收"}</Tag>
          {quality ? "观察RTT样本" : "合成范围 6.5–13.0 Gbps"}
        </Text>
        <Text>
          <Tag color="cyan">{quality ? "p50" : "发送"}</Tag>
          {quality ? "非应用响应时间" : "合成范围 3.5–7.5 Gbps"}
        </Text>
      </div>
    </>
  );
}

function Carriers() {
  return (
    <>
      <Paragraph type="secondary">观察字节占比 · 类别相斥 · 合成数据</Paragraph>
      <div className="design-bars" aria-label="TCP 68%，UDP 27%，其他IP 5%">
        <span style={{ width: "68%", background: "#1677ff" }} />
        <span style={{ width: "27%", background: "#13a8a8" }} />
        <span style={{ width: "5%", background: "#bfbfbf" }} />
      </div>
      <List
        size="small"
        dataSource={[
          ["TCP", "68%", "1.36 TB"],
          ["UDP", "27%", "0.54 TB"],
          ["其他 IP", "5%", "0.10 TB"],
        ]}
        renderItem={(item) => (
          <List.Item>
            <Text>{item[0]}</Text>
            <Space>
              <Text strong>{item[1]}</Text>
              <Text type="secondary">{item[2]}</Text>
            </Space>
          </List.Item>
        )}
      />
      <Paragraph type="secondary" style={{ marginTop: 16 }}>
        TLS／QUIC 头候选不叠加到本分母。
      </Paragraph>
    </>
  );
}

function Topology({
  layer = "physical",
  onSelect,
}: {
  layer?: string;
  onSelect: (label: string) => void;
}) {
  const { token } = theme.useToken();
  const nodes = [
    { id: "a", x: 80, y: 140, name: "上联路由", type: "受管边界" },
    { id: "b", x: 270, y: 140, name: "CORE-GW-01", type: "核心网关" },
    { id: "c", x: 470, y: 62, name: "AGG-SW-02", type: "汇聚交换机" },
    { id: "d", x: 470, y: 220, name: "SEC-FW-01", type: "安全设备" },
    { id: "e", x: 660, y: 140, name: "OBS-01", type: "观测节点" },
  ];
  return (
    <svg
      className="design-chart"
      viewBox="0 0 760 325"
      aria-label={`${layer === "physical" ? "物理证据" : "区域通信"}合成拓扑。五个受管节点，按Tab可选择节点证据。`}
    >
      {[
        [0, 1],
        [1, 2],
        [1, 3],
        [2, 4],
        [3, 4],
      ].map(([a, b], i) => (
        <g key={`${a}-${b}`}>
          <path
            d={`M ${nodes[a].x} ${nodes[a].y} C ${(nodes[a].x + nodes[b].x) / 2} ${nodes[a].y}, ${(nodes[a].x + nodes[b].x) / 2} ${nodes[b].y}, ${nodes[b].x} ${nodes[b].y}`}
            stroke={i === 2 ? token.colorWarning : token.colorPrimaryBorder}
            strokeWidth={layer === "physical" ? 2 : 4}
            strokeDasharray={i === 2 || i === 4 ? "5 5" : undefined}
            fill="none"
          />
          <text
            x={(nodes[a].x + nodes[b].x) / 2}
            y={(nodes[a].y + nodes[b].y) / 2 - 12}
            fill={token.colorTextSecondary}
            textAnchor="middle"
            fontSize="11"
          >
            {layer === "physical"
              ? ["100G", "40G", "待核实", "10G", "待核实"][i]
              : ["12.8G", "6.2G", "2.1G", "0.8G", "未知"][i]}
          </text>
        </g>
      ))}
      {nodes.map((n) => (
        <g
          key={n.id}
          role="button"
          tabIndex={0}
          aria-label={`查看${n.name}合成证据`}
          onClick={() => onSelect(n.name)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              onSelect(n.name);
            }
          }}
        >
          <rect
            x={n.x - 36}
            y={n.y - 25}
            width="72"
            height="50"
            rx="8"
            fill={token.colorPrimaryBg}
            stroke={token.colorPrimary}
          />
          <text
            x={n.x}
            y={n.y + 4}
            textAnchor="middle"
            fontSize="14"
            fill={token.colorPrimary}
          >
            {n.id.toUpperCase()}
          </text>
          <text
            x={n.x}
            y={n.y + 48}
            textAnchor="middle"
            fontSize="12"
            fill={token.colorText}
          >
            {n.name}
          </text>
          <text
            x={n.x}
            y={n.y + 67}
            textAnchor="middle"
            fontSize="11"
            fill={token.colorTextSecondary}
          >
            {n.type}
          </text>
        </g>
      ))}
      <text x="24" y="310" fill={token.colorTextSecondary} fontSize="12">
        实线：合成已核实关系 · 虚线：合成待核实关系 · 容量缺失时不计算利用率
      </text>
    </svg>
  );
}

function Matrix() {
  const { token } = theme.useToken();
  const [selected, setSelected] = useState("核心区 → 服务区：12.4 GB");
  const zones = ["核心区", "汇聚区", "服务区", "观测区"];
  const values = [
    [0, 8.1, 12.4, 1.1],
    [6.2, 0, 4.8, 0.7],
    [8.9, 2.1, 0, 0.4],
    [0.5, 0.3, 0.9, 0],
  ];
  return (
    <>
      <Table
        size="small"
        pagination={false}
        scroll={{ x: 460 }}
        dataSource={zones.map((name, row) => ({ key: name, name, row }))}
        columns={[
          { title: "源 / 目的", dataIndex: "name", width: 100 },
          ...zones.map((zone, col) => ({
            title: zone,
            key: zone,
            render: (_: unknown, record: { row: number }) => (
              <Button
                block
                size="small"
                type={values[record.row][col] > 7 ? "primary" : "default"}
                aria-label={`${zones[record.row]}到${zone} ${values[record.row][col]} GB`}
                onClick={() =>
                  setSelected(
                    `${zones[record.row]} → ${zone}：${values[record.row][col]} GB`,
                  )
                }
              >
                {values[record.row][col]}
              </Button>
            ),
          })),
        ]}
      />
      <Paragraph style={{ marginTop: 16, color: token.colorTextSecondary }}>
        {selected} · 仅合成区域聚合，无公众终端明细
      </Paragraph>
    </>
  );
}

function currentPage(): Page {
  const requested = window.location.hash.slice(1);
  return Object.hasOwn(titles, requested) ? (requested as Page) : "overview";
}

function Preview() {
  const [dark, setDark] = useState(false);
  return (
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
        token: { colorPrimary: "#1677ff" },
      }}
    >
      <App>
        <Console dark={dark} setDark={setDark} />
      </App>
    </ConfigProvider>
  );
}

function Console({
  dark,
  setDark,
}: {
  dark: boolean;
  setDark: (value: boolean) => void;
}) {
  const { message } = App.useApp();
  const screens = Grid.useBreakpoint();
  const [page, setPage] = useState<Page>(currentPage);
  const [scope, setScope] = useState("all");
  const [layer, setLayer] = useState("physical");
  const [drawer, setDrawer] = useState<string | null>(null);
  const [task, setTask] = useState<
    "none" | "preview" | "accepted" | "verified"
  >("none");
  const [eventState, setEventState] = useState("新建");
  useEffect(() => {
    const listener = () => {
      setPage(currentPage());
      setDrawer(null);
    };
    window.addEventListener("hashchange", listener);
    return () => window.removeEventListener("hashchange", listener);
  }, []);
  const rows =
    scope === "core" ? assetRows.filter((x) => x.zone === "核心区") : assetRows;
  const showEvidence = (label: string) => setDrawer(label);
  const filters = (
    <Space wrap>
      {(page === "overview" || page === "asset") && (
        <Select
          aria-label="资产表演示筛选"
          value={scope}
          onChange={setScope}
          style={{ width: 220 }}
          options={[
            { value: "all", label: "资产表：全部受管样例" },
            { value: "core", label: "资产表：核心区样例" },
          ]}
        />
      )}
      <Tag icon={<ClockCircleOutlined />}>固定样本 09:00–10:00 UTC+8</Tag>
      <Text type="secondary">2026-10-27 · 图表为固定合成快照</Text>
    </Space>
  );
  return (
    <ProLayout
      title="CythSec"
      logo={<DeploymentUnitOutlined />}
      layout="mix"
      navTheme={dark ? "realDark" : "light"}
      siderWidth={224}
      fixedHeader
      fixSiderbar
      route={{ routes: navigation }}
      location={{ pathname: `/${page}` }}
      menuItemRender={(item, dom) => (
        <a href={`#${item.path?.slice(1)}`}>{dom}</a>
      )}
      actionsRender={() => [
        <Tag key="mode" color="blue">
          {screens.md ? "设计预览 v1.1" : "设计稿"}
        </Tag>,
        <Switch
          key="theme"
          aria-label="深色主题"
          checked={dark}
          onChange={setDark}
          checkedChildren="深色"
          unCheckedChildren="浅色"
        />,
      ]}
      avatarProps={{
        icon: <InfoCircleOutlined />,
        title: screens.md ? "演示模式 · 无真实身份" : undefined,
      }}
    >
      <PageContainer
        title={titles[page][0]}
        subTitle={titles[page][1]}
        breadcrumb={{
          items: [{ title: "设计工作区" }, { title: titles[page][0] }],
        }}
      >
        <div className="design-page">
          <Alert
            showIcon
            type="info"
            title="独立设计演示 · 全部为合成数据 · 未连接后端或实际设备"
            description="不读取真实流量，不发送通知，不执行设备配置。数字、关系和任务回执仅用于评审布局与交互。"
          />
          {filters}
          {page === "overview" && (
            <>
              <Metrics
                items={[
                  ["接收速率", "12.8", "Gbps", "合成测量值 · 非实测容量"],
                  ["受管资产", rows.length, "项", "示例目录 · 不含过境终端"],
                  ["来源质量", "2 / 3", "正常", "1项解析异常待处理"],
                  ["待处理事件", 3, "项", "合成基础设施事件"],
                ]}
              />
              <div className="design-row">
                <ProCard
                  title="接口收发趋势"
                  extra={<Tag>V01 · 合成</Tag>}
                  variant="outlined"
                >
                  <Trend />
                </ProCard>
                <ProCard
                  title="承载协议构成"
                  extra={<Tag>V02 · 合成</Tag>}
                  variant="outlined"
                >
                  <Carriers />
                </ProCard>
              </div>
              <div className="design-row">
                <ProCard
                  title="受管基础设施关系"
                  extra={
                    <Button type="link" href="#topology">
                      打开拓扑
                    </Button>
                  }
                  variant="outlined"
                >
                  <Topology onSelect={showEvidence} />
                </ProCard>
                <ProCard title="数据覆盖与完整性" variant="outlined">
                  <List
                    dataSource={[
                      ["目录关联", "已核实"],
                      ["接口计数", "正常"],
                      ["IDS 事件解析", "异常"],
                      ["镜像丢失真值", "未提供"],
                    ]}
                    renderItem={(item) => (
                      <List.Item>
                        <Text>{item[0]}</Text>
                        <Status value={item[1]} />
                      </List.Item>
                    )}
                  />
                  <Alert
                    type="warning"
                    showIcon
                    title="未知不是零"
                    description="源计数缺失时，不显示“零丢包”或完整覆盖。"
                  />
                </ProCard>
              </div>
            </>
          )}
          {page === "topology" && (
            <>
              <div className="design-caption">
                <Radio.Group
                  aria-label="拓扑图层"
                  value={layer}
                  onChange={(e) => setLayer(e.target.value)}
                  optionType="button"
                  options={[
                    { value: "physical", label: "物理证据" },
                    { value: "communications", label: "区域通信" },
                  ]}
                />
                <Text type="secondary">
                  当前仅5个合成节点 · 点击节点查看证据
                </Text>
              </div>
              <ProCard
                title={
                  layer === "physical" ? "物理关系与容量" : "区域级通信示意"
                }
                variant="outlined"
              >
                <Topology layer={layer} onSelect={showEvidence} />
              </ProCard>
              <div className="design-row-even">
                <ProCard title="关系证据表" variant="outlined">
                  <Table
                    size="small"
                    rowKey="id"
                    pagination={false}
                    dataSource={[
                      {
                        id: "e1",
                        a: "CORE-GW-01",
                        b: "AGG-SW-02",
                        evidence: "合成库存 + LLDP",
                        state: "已核实",
                      },
                      {
                        id: "e2",
                        a: "SEC-FW-01",
                        b: "OBS-01",
                        evidence: "仅目录声明",
                        state: "待核实",
                      },
                    ]}
                    columns={[
                      { title: "源", dataIndex: "a" },
                      { title: "目的", dataIndex: "b" },
                      { title: "依据", dataIndex: "evidence" },
                      {
                        title: "状态",
                        dataIndex: "state",
                        render: (v) => <Status value={v} />,
                      },
                    ]}
                    scroll={{ x: 560 }}
                  />
                </ProCard>
                <ProCard
                  title="区域通信矩阵"
                  extra={<Tag>V09 · GB · 合成</Tag>}
                  variant="outlined"
                >
                  <Matrix />
                </ProCard>
              </div>
            </>
          )}
          {page === "asset" && (
            <div className="design-asset">
              <ProCard title="资产证据摘要" variant="outlined">
                <Space direction="vertical" size={18}>
                  <SafetyCertificateOutlined style={{ fontSize: 36 }} />
                  <Title level={4}>CORE-GW-01</Title>
                  <Status value="已核实" />
                  <Text type="secondary">ASSET-DEMO-GW01</Text>
                  <Descriptions
                    column={1}
                    size="small"
                    items={[
                      { key: "kind", label: "类型", children: "受管核心网关" },
                      {
                        key: "domain",
                        label: "观测域",
                        children: "核心区 / VRF-DEMO",
                      },
                      {
                        key: "ip",
                        label: "管理地址",
                        children: (
                          <Text className="design-address">192.0.2.1</Text>
                        ),
                      },
                      {
                        key: "mac",
                        label: "本链路MAC",
                        children: (
                          <Text className="design-address">
                            02:00:00:00:00:01
                          </Text>
                        ),
                      },
                      {
                        key: "team",
                        label: "维护团队",
                        children: "网络运维组（合成）",
                      },
                    ]}
                  />
                  <Alert
                    showIcon
                    title="MAC仅为本链路证据"
                    description="不代表远端终端地址，不建立使用者身份关联。"
                    type="info"
                  />
                </Space>
              </ProCard>
              <div className="design-content">
                <ProCard variant="outlined">
                  <Tabs
                    items={[
                      {
                        key: "summary",
                        label: "技术概要",
                        children: (
                          <div className="design-stack">
                            <Space wrap>
                              <Tag>管理：已登记</Tag>
                              <Tag color="success">连接证据：正常</Tag>
                              <Tag color="warning">质量：待关注</Tag>
                              <Tag>事件：1项未解决</Tag>
                            </Space>
                            <Title level={5}>RTT观察分位趋势</Title>
                            <Trend quality />
                            <Button
                              onClick={() =>
                                showEvidence("CORE-GW-01 地址关联")
                              }
                            >
                              查看地址关联证据
                            </Button>
                          </div>
                        ),
                      },
                      {
                        key: "address",
                        label: "地址与邻居",
                        children: (
                          <Descriptions
                            column={1}
                            bordered
                            items={[
                              {
                                key: "ip",
                                label: "地址与有效范围",
                                children:
                                  "192.0.2.1 · VRF-DEMO · 合成固定管理地址",
                              },
                              {
                                key: "mac",
                                label: "MAC观察",
                                children:
                                  "02:00:00:00:00:01 · 本地管理地址 · 仅本链路",
                              },
                              {
                                key: "evidence",
                                label: "支持证据",
                                children: "合成设备目录 + 合成只读接口",
                              },
                              {
                                key: "time",
                                label: "有效期",
                                children:
                                  "2026-10-27 09:00–10:00 UTC+8（合成）",
                              },
                            ]}
                          />
                        ),
                      },
                      {
                        key: "relations",
                        label: "邻接关系",
                        children: <Topology onSelect={showEvidence} />,
                      },
                      {
                        key: "event",
                        label: "关联事件",
                        children: (
                          <Alert
                            type="warning"
                            showIcon
                            title="接口丢弃计数持续上升（合成）"
                            action={<Button href="#incident">查看事件</Button>}
                          />
                        ),
                      },
                    ]}
                  />
                </ProCard>
              </div>
            </div>
          )}
          {page === "integrations" && (
            <>
              <Metrics
                items={[
                  ["已配置连接器", 3, "项", "合成适配器，无厂商兼容声明"],
                  ["解析正常", 2, "项", "传输成功与解析成功独立"],
                  ["结果未知", 1, "项", "不可计入已验证"],
                  ["外部动作", 0, "次", "本预览绝不投递"],
                ]}
              />
              <ProCard
                title="设备与连接器"
                extra={<Tag>传输 / 解析 / 核对 三态</Tag>}
                variant="outlined"
              >
                <Table
                  rowKey="key"
                  size="middle"
                  dataSource={connectors}
                  pagination={false}
                  scroll={{ x: 850 }}
                  columns={[
                    { title: "连接器", dataIndex: "name" },
                    { title: "适配器", dataIndex: "adapter" },
                    {
                      title: "传输",
                      dataIndex: "transport",
                      render: (v) => <Status value={v} />,
                    },
                    {
                      title: "解析",
                      dataIndex: "parse",
                      render: (v) => <Status value={v} />,
                    },
                    {
                      title: "业务核对",
                      dataIndex: "verify",
                      render: (v) => <Status value={v} />,
                    },
                    { title: "样例事件", dataIndex: "events" },
                    { title: "延迟", dataIndex: "delay" },
                    {
                      title: "操作",
                      render: (_, r) => (
                        <Button
                          type="link"
                          onClick={() => showEvidence(r.name)}
                        >
                          证据
                        </Button>
                      ),
                    },
                  ]}
                />
              </ProCard>
              <ProCard
                title="工单协作阶段演示"
                extra={<Tag color="blue">本地模拟，不发送</Tag>}
                variant="outlined"
              >
                <Paragraph type="secondary">
                  预览 → 对端接受 →
                  对账验证。每一步均由演示按钮推进，无网络请求。
                </Paragraph>
                <Steps
                  status={task === "verified" ? "finish" : "process"}
                  current={
                    task === "none"
                      ? 0
                      : task === "preview"
                        ? 1
                        : task === "accepted"
                          ? 2
                          : 3
                  }
                  items={[
                    { title: "草稿" },
                    { title: "预览已生成" },
                    { title: "对端已接受" },
                    { title: "已验证" },
                  ]}
                />
                <Space wrap className="design-task">
                  <Button onClick={() => setTask("preview")}>
                    生成合成预览
                  </Button>
                  <Button
                    disabled={task !== "preview"}
                    onClick={() => setTask("accepted")}
                  >
                    模拟接收回执
                  </Button>
                  <Button
                    disabled={task !== "accepted"}
                    onClick={() => setTask("verified")}
                  >
                    模拟对账一致
                  </Button>
                  <Button onClick={() => setTask("none")}>重置演示</Button>
                  <Tag color={task === "verified" ? "success" : "warning"}>
                    {task === "accepted"
                      ? "对端已接受，结果尚未核对"
                      : task === "verified"
                        ? "合成对象已核对（非真实执行）"
                        : "无外部动作"}
                  </Tag>
                </Space>
              </ProCard>
            </>
          )}
          {page === "incident" && (
            <>
              <Space wrap>
                <Tag color="warning">来源级别：中</Tag>
                <Tag>归一化：中 · 映射demo-v1</Tag>
                <Status value={eventState} />
                <Button
                  disabled={eventState === "已确认"}
                  onClick={() => {
                    setEventState("已确认");
                    void message.info("仅更新本地演示状态，未写入服务端");
                  }}
                >
                  演示确认事件
                </Button>
                <Button href="#integrations">查看协作演示</Button>
              </Space>
              <div className="design-row">
                <ProCard title="事件与证据时间线" variant="outlined">
                  <Timeline
                    items={[
                      {
                        children: (
                          <>
                            <Text strong>09:32:10 · 来源观察</Text>
                            <Paragraph>
                              受管接口discards计数增量上升，合成样本；不推断攻击或确定丢包率。
                            </Paragraph>
                          </>
                        ),
                      },
                      {
                        children: (
                          <>
                            <Text strong>09:32:12 · 平台接收</Text>
                            <Paragraph>
                              事件字段归一化，目录引用已核实，来源时钟质量为演示值。
                            </Paragraph>
                          </>
                        ),
                      },
                      {
                        color: "orange",
                        children: (
                          <>
                            <Text strong>09:33:00 · 证据缺口</Text>
                            <Paragraph>
                              镜像侧缺少独立丢失真值，不能确认端到端业务影响。
                            </Paragraph>
                          </>
                        ),
                      },
                      {
                        children: (
                          <Button
                            onClick={() =>
                              showEvidence("SEC-DEMO-027 来源证据")
                            }
                          >
                            展开合成证据摘要
                          </Button>
                        ),
                      },
                    ]}
                  />
                </ProCard>
                <ProCard title="受管资源与调查范围" variant="outlined">
                  <Descriptions
                    column={1}
                    items={[
                      {
                        key: "asset",
                        label: "资产",
                        children: <a href="#asset">CORE-GW-01</a>,
                      },
                      {
                        key: "scope",
                        label: "范围",
                        children: "核心区 / VRF-DEMO",
                      },
                      {
                        key: "source",
                        label: "来源",
                        children: "合成只读接口计数",
                      },
                      {
                        key: "binding",
                        label: "资产关联",
                        children: "目录+接口证据（合成）",
                      },
                      { key: "impact", label: "业务影响", children: "未核验" },
                    ]}
                  />
                  <Alert
                    type="info"
                    showIcon
                    title="事件确认不等于故障已消除"
                    description="来源恢复、平台结案和工单结果是独立状态。"
                  />
                </ProCard>
              </div>
              <ProCard title="接口质量观察" variant="outlined">
                <Trend quality />
              </ProCard>
            </>
          )}
          {(page === "overview" || page === "asset") && (
            <div className="design-table">
              <ProTable<(typeof assetRows)[number]>
                headerTitle="受管资产样例"
                rowKey="key"
                search={false}
                options={false}
                pagination={false}
                dataSource={rows}
                scroll={{ x: 800 }}
                columns={[
                  {
                    title: "资产",
                    dataIndex: "name",
                    render: (_, r) => (
                      <Button type="link" onClick={() => showEvidence(r.name)}>
                        {r.name}
                      </Button>
                    ),
                  },
                  { title: "类型", dataIndex: "type" },
                  { title: "管理IP", dataIndex: "ip" },
                  { title: "区域", dataIndex: "zone" },
                  {
                    title: "关联",
                    dataIndex: "state",
                    render: (_, r) => <Status value={r.state} />,
                  },
                  { title: "证据", dataIndex: "source" },
                ]}
              />
            </div>
          )}
          <Paragraph type="secondary">
            设计稿 v1.1 · 技术资产与网络聚合 · 无个人身份字段 ·
            所有示例值均为合成 · 生产能力以实际后端发布与验收为准
          </Paragraph>
        </div>
      </PageContainer>
      <Drawer
        title={`${drawer ?? ""} · 合成证据`}
        open={drawer !== null}
        onClose={() => setDrawer(null)}
        width={480}
      >
        {drawer ? (
          <Space direction="vertical" size={20} style={{ width: "100%" }}>
            <Alert showIcon type="info" title="设计示意，无真实设备数据" />
            <Descriptions
              column={1}
              bordered
              items={[
                {
                  key: "source",
                  label: "来源",
                  children: "合成目录 / 接口快照",
                },
                {
                  key: "time",
                  label: "时间",
                  children: "2026-10-27 10:00 UTC+8",
                },
                { key: "scope", label: "范围", children: "明确纳管的基础设施" },
                {
                  key: "method",
                  label: "方法",
                  children: "目录与观察证据分层",
                },
                {
                  key: "limit",
                  label: "缺口",
                  children: "不证明远端MAC、端到端可达或实际安全检测能力",
                },
              ]}
            />
            <Button href="#asset" onClick={() => setDrawer(null)}>
              查看资产技术档案
            </Button>
          </Space>
        ) : (
          <Empty />
        )}
      </Drawer>
    </ProLayout>
  );
}

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("Design preview root element is missing");
createRoot(rootElement).render(<Preview />);
