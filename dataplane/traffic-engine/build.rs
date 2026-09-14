// build.rs - 构建期版本注入。
//
// 设计要点：仓库根 `VERSION` 是版本号的**唯一真源**。Rust 侧此前用
// `env!("CARGO_PKG_VERSION")` 取值，那实际来自 Cargo.toml 里另写一遍的
// 字面量 —— 于是同一个版本号在仓库里存在三份独立副本（VERSION / 根
// Cargo.toml / 本包 Cargo.toml），改一处不会传播，属于「看起来单一真源、
// 实际多处声明」的假象。
//
// 本脚本在编译期读取根 VERSION，注入为环境变量供 `env!` 取用，
// 使产物实际报告的值一定等于 VERSION 的内容。
//
// 零第三方依赖：只用 std。项目原则之一是离线可构建，引入 toml/chrono
// 之类的 crate 只为读版本与取时间并不划算。

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // CARGO_MANIFEST_DIR 指向 dataplane/traffic-engine，故上溯两级到仓库根。
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR 未设置（应由 cargo 注入）");
    let version_file = Path::new(&manifest_dir).join("../../VERSION");

    // 版本文件变更必须触发重编译，否则改了 VERSION 而产物版本号不变 ——
    // 那正是「单一真源失效」最难察觉的表现形式。
    println!("cargo:rerun-if-changed={}", version_file.display());

    let version = read_version(&version_file);

    println!("cargo:rustc-env=CYTHSEC_VERSION={version}");
    println!("cargo:rustc-env=CYTHSEC_COMMIT={}", git_commit());
    println!("cargo:rustc-env=CYTHSEC_BUILD_TIME={}", build_time());
}

// read_version 读取并规范化版本号。
//
// 读不到时**直接让构建失败**，而不是回落到一个占位值：静默回落会让产物
// 报告一个看似正常却错误的版本号，比构建失败更危险。
fn read_version(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(raw) => {
            let v = raw.trim();
            if v.is_empty() {
                panic!("版本真源文件为空: {}", path.display());
            }
            v.to_string()
        }
        Err(e) => panic!("无法读取版本真源文件 {}: {e}", path.display()),
    }
}

// git_commit 返回短提交哈希；非 git 工作树（如源码包解压）回落 unknown。
fn git_commit() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

// build_time 返回 UTC 的 RFC3339 时间戳，与 Go 侧 -ldflags 注入的格式一致。
//
// 优先调用系统 `date`（Linux/macOS 均有）；不可用时回落到 Unix 秒数 ——
// 回落值仍可比较与排序，只是不如 RFC3339 可读，故不阻断构建。
fn build_time() -> String {
    if let Ok(out) = Command::new("date").args(["-u", "+%Y-%m-%dT%H:%M:%SZ"]).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => format!("epoch:{}", d.as_secs()),
        Err(_) => "unknown".to_string(),
    }
}
