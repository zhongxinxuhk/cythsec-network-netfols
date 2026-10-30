// dump_ddl.rs —— 把列契约真源导出为**建表 DDL** 与**列映射表**（CYS-STO-002）。
//
// ## 为什么单独一个二进制
//
// DDL 与"列 ↔ JSONL 路径"的映射都是**手抄最容易出事**的两处：
//   * 手写 DDL 时，改一列代码忘改 SQL 的表现是"插入报列数不符"（还好），
//     或者更糟 —— ClickHouse 建表成功，而那列的值永远来自另一列。
//   * 对照脚本手写映射时，改一列的表现是"那一列不再被比对"，而脚本仍报全绿。
// 所以两者都由 `storage::flow_columns()` 生成，脚本消费生成物而不是复制它。
//
// ## 输出
//
// * 默认：`flows` 的 `CREATE TABLE`（写 stdout）。
// * `--columns-tsv`：每行 `列名<TAB>类型<TAB>块<TAB>JSONL 路径<TAB>注释`，
//   供 `scripts/verify/check-columnar.sh` 的对照器取期望值。
//   （注意：TSV 里**不含**期望值本身，值仍从 JSONL 读 —— 见下条。）
// * `--contract`：一行契约摘要（版本 + 列数），门禁用它判断"生成物是否过期"。
//
// ## 自证边界（照实说）
//
// 期望值来自我们自己产出的 JSONL，因此"值对不对"的外部裁判是**参考实现对字节的解码**
// （`clickhouse local` 读我们的产物）与**逐字节 parity**（参考实现重写一遍同样的逻辑行）；
// 本二进制只保证"映射与列清单同源"。缺参考实现时，门禁必须显式打印「未核验」，
// 不能把"自己对自己"显示成通过。

use std::io::{self, Write};
use std::process::ExitCode;

use traffic_engine::storage::{
    ddl_flows, flow_columns, native::DEFAULT_ROWS_PER_BLOCK, ColumnSpec, COLUMN_CONTRACT_VERSION,
    TABLE_NAME,
};

const USAGE: &str = "\
cythsec-dump-ddl —— 从列契约真源生成 ClickHouse DDL 与列映射表

用法:
  cythsec-dump-ddl [--ttl-days N] [--columns-tsv] [--contract]

选项:
  --ttl-days N     数据保留天数（默认 90；0 = 不生成 TTL 子句）
  --columns-tsv    输出列映射表（列名/类型/块/JSONL 路径/注释），不是 DDL
  --contract       输出一行契约摘要（版本 + 列数 + 默认每块行数）
  -h, --help       打印本帮助
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut ttl: u32 = 90;
    let mut mode = Mode::Ddl;
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--columns-tsv" => mode = Mode::Tsv,
            "--contract" => mode = Mode::Contract,
            "--ttl-days" => {
                let Some(v) = argv.get(i + 1) else {
                    eprintln!("cythsec-dump-ddl 错误: --ttl-days 需要一个参数");
                    return ExitCode::FAILURE;
                };
                ttl = match v.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        eprintln!("cythsec-dump-ddl 错误: --ttl-days 需要非负整数，得到 `{v}`");
                        return ExitCode::FAILURE;
                    }
                };
                i += 1;
            }
            other => {
                eprintln!("cythsec-dump-ddl 错误: 不认识参数 `{other}`");
                eprint!("{USAGE}");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let r = match mode {
        Mode::Ddl => out
            .write_all(ddl_flows(ttl).as_bytes())
            .map_err(|e| format!("写 DDL 失败：{e}")),
        Mode::Tsv => write_tsv(&mut out),
        Mode::Contract => write_contract(&mut out, ttl),
    };
    let _ = out.flush();
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("cythsec-dump-ddl 错误: {msg}");
            ExitCode::FAILURE
        }
    }
}

enum Mode {
    Ddl,
    Tsv,
    Contract,
}

/// 对照器取期望值的规则（**集中在这里**，不散落到脚本里）。
///
/// 为什么需要显式规则而不是"按列名去 JSONL 里找"：有 4 类列的期望值不是 JSONL 里的
/// 一个现成取值 —— 常量、地址族、地址文本、时长的钳位口径。让每条规则在 TSV 里
/// 指名道姓，脚本遇到不认识的规则就**判红**；如果脚本靠"猜列名"取值，
/// 加一列而忘了处理它的表现是"这一列静静不比对"，而全绿照常打印。
fn expectation_for(c: &ColumnSpec) -> String {
    match c.name {
        "column_contract_version" => format!("const:{}", COLUMN_CONTRACT_VERSION),
        "ip_family" => "derived:family".to_string(),
        "src_ip" => "derived:ip_text:flow.src_ip".to_string(),
        "dst_ip" => "derived:ip_text:flow.dst_ip".to_string(),
        "duration_us" => "derived:duration_us".to_string(),
        _ => {
            if c.jsonl_path.contains("(派生)") {
                // 新加的派生列忘了登记规则 ⇒ 让 TSV 里出现一条没人认领的 unknown，
                // 对照器会因此判红（而不是悄悄跳过）。
                format!("unknown:{}", c.jsonl_path)
            } else {
                format!("json:{}", c.jsonl_path)
            }
        }
    }
}

fn write_tsv(out: &mut impl Write) -> Result<(), String> {
    for c in flow_columns() {
        // 注释里的制表符/换行会让 TSV 错位，而"错位"在这里的表现是某一列被跳过。
        let comment = c.comment.replace(['\t', '\n'], " ");
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}",
            c.name,
            c.ch_type(),
            c.group,
            c.jsonl_path,
            expectation_for(&c),
            comment
        )
        .map_err(|e| format!("写 TSV 失败：{e}"))?;
    }
    Ok(())
}

fn write_contract(out: &mut impl Write, ttl: u32) -> Result<(), String> {
    let cols = flow_columns();
    writeln!(
        out,
        "table={TABLE_NAME} column_contract_version={COLUMN_CONTRACT_VERSION} columns={} nullable={} rows_per_block={DEFAULT_ROWS_PER_BLOCK} ttl_days={ttl}",
        cols.len(),
        cols.iter().filter(|c| c.nullable).count(),
    )
    .map_err(|e| format!("写契约失败：{e}"))
}
