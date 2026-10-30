-- native 写入器的重试 token 需要非复制 MergeTree 启用有限去重窗口。
-- 窗口按 block_id 数量计，不是永久 exactly-once；部署时按重试时长与写入速率标定。
ALTER TABLE flow_records_v2
MODIFY SETTING non_replicated_deduplication_window = 10000;
