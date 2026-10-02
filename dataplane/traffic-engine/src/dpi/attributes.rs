// dpi/attributes.rs —— DPI 结果落地成 `ATTR_*` 属性。
//
// 本文件闭合的是一个已经存在很久的缺口：属性字典（configs/registry/attributes.json）里
// 早就登记了 `ATTR_TLS_SNI` / `ATTR_TLS_JA3` / `ATTR_DNS_QNAME` / `ATTR_APP_ID` 等一整套
// L7 词汇，规则示例与生成物里也都在引用它们 —— 但**没有任何代码真正产出过它们**。
// 契约层与实现层之间隔着一层空气，规则写得出来却永远不会命中。
//
// 两条硬约束：
//   1. **只产出已登记属性**。标识常量全部引用 `attributes_gen`（由真源生成），
//      本文件不允许出现手写的 "ATTR_..." 字面量 —— 手写一份就等于多一份真源，
//      改了字典不改这里，规则会静默地再也匹配不上。
//   2. **未识别≠识别为无**。SNI 为 None 时**不产出** `ATTR_TLS_SNI`，而不是产出空串。
//      规则里 `tls.sni == ""` 与"这条流的 SNI 我们根本不知道"是两回事：
//      产出空串会让"有多少流量没有 SNI"这个指标凭空多算一大批（ECH 流量全中招）。

use super::types::{AppId, Detection};
use crate::attributes_gen::{self, AttrType};

/// 一条属性产出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    /// 规范标识，取值来自 `attributes_gen` 的常量。
    pub id: &'static str,
    /// 真源里登记的该属性类型，产出时就钉住，避免下游再猜。
    pub ty: AttrType,
    /// 标量化后的值（跨语言通道与规则引擎的统一表示）。
    pub scalar: String,
}

impl Attr {
    fn new(id: &'static str, ty: AttrType, scalar: impl Into<String>) -> Self {
        Self {
            id,
            ty,
            scalar: scalar.into(),
        }
    }

    /// 按真源登记的类型校验标量值。
    ///
    /// 规则引擎在编译规则时会拒绝类型对不上的字面量；把校验提前到产出侧，
    /// 能把"规则写错了"和"属性产出错了"区分开 —— 否则两类问题都表现为
    /// 规则在编译期炸掉，排查时只能猜是哪一边。
    pub fn validate(&self) -> Result<(), AttrError> {
        match attributes_gen::lookup(self.id) {
            None => return Err(AttrError::Unregistered(self.id)),
            Some(def) if def.ty != self.ty => {
                return Err(AttrError::TypeMismatch(self.id, def.ty, self.ty))
            }
            Some(_) => {}
        }
        match self.ty {
            AttrType::String | AttrType::Enum | AttrType::StringSet => {
                if self.scalar.is_empty() {
                    return Err(AttrError::Empty(self.id));
                }
            }
            AttrType::U8 => self.parse_as::<u8>()?,
            AttrType::U16 => self.parse_as::<u16>()?,
            AttrType::U32 => self.parse_as::<u32>()?,
            AttrType::U64 => self.parse_as::<u64>()?,
            AttrType::IP => {
                if self.scalar.parse::<std::net::IpAddr>().is_err() {
                    return Err(AttrError::BadScalar(self.id));
                }
            }
            // 其余类型（bytes / ip_prefix / port / bool / i64 / time_ms）当前阶段不产出，
            // 不做无依据的放行也不做无依据的拒绝。
            _ => {}
        }
        Ok(())
    }

    fn parse_as<T: std::str::FromStr>(&self) -> Result<(), AttrError> {
        self.scalar
            .parse::<T>()
            .map(|_| ())
            .map_err(|_| AttrError::BadScalar(self.id))
    }
}

/// 属性产出错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrError {
    /// 标识没有登记在属性字典里 —— 规则引擎不认识它。
    Unregistered(&'static str),
    /// 与登记类型不符。
    TypeMismatch(&'static str, AttrType, AttrType),
    /// 标量无法按登记类型解析。
    BadScalar(&'static str),
    /// 文本类属性不允许为空串（空串应改为"不产出"）。
    Empty(&'static str),
}

/// 把一次检测结果落地成属性集合。
pub fn emit(d: &Detection) -> Vec<Attr> {
    let mut out = Vec::new();

    // 应用标识只在真的识别出来时产出：把 unknown 也写进去，
    // "已识别应用占比"这个指标的分母会被撑满，指标就废了。
    if d.app != AppId::Unknown {
        out.push(Attr::new(
            attributes_gen::ATTR_APP_ID,
            AttrType::U32,
            d.app.as_u32().to_string(),
        ));
    }

    if let Some(sni) = &d.sni {
        out.push(Attr::new(
            attributes_gen::ATTR_TLS_SNI,
            AttrType::String,
            sni,
        ));
    }
    if let Some(ja3) = &d.ja3 {
        out.push(Attr::new(
            attributes_gen::ATTR_TLS_JA3,
            AttrType::String,
            ja3,
        ));
    }
    if let Some(v) = d.tls_version {
        out.push(Attr::new(
            attributes_gen::ATTR_TLS_VERSION,
            AttrType::Enum,
            tls_version_name(v),
        ));
    }
    if let Some(m) = &d.method {
        out.push(Attr::new(
            attributes_gen::ATTR_HTTP_METHOD,
            AttrType::Enum,
            m,
        ));
    }
    if let Some(h) = &d.host {
        out.push(Attr::new(
            attributes_gen::ATTR_HTTP_HOST,
            AttrType::String,
            h,
        ));
    }
    if let Some(q) = &d.qname {
        out.push(Attr::new(
            attributes_gen::ATTR_DNS_QNAME,
            AttrType::String,
            q,
        ));
    }
    if let Some(qt) = d.qtype {
        out.push(Attr::new(
            attributes_gen::ATTR_DNS_QTYPE,
            AttrType::U16,
            qt.to_string(),
        ));
    }

    // SNI / HTTP Host 归一到同一个域名属性：规则只要写一个 `server.fqdn == x`
    // 就能同时覆盖明文与加密流量，而不必为三种来源各写一条。
    if let Some(fqdn) = d.server_fqdn() {
        out.push(Attr::new(
            attributes_gen::ATTR_SERVER_FQDN,
            AttrType::String,
            fqdn,
        ));
    }

    out
}

/// TLS 版本号的规则字面量命名：`tls1.3` / `tls1.2` / `tls1.1` / `tls1.0` / `ssl3.0`。
///
/// 用名字而不是 `0x0303` 这种线格值：规则是人写的，写 `tls1.2` 的人不会把 `0x0303` 记错，
/// 但反过来每次都要查表。取值不在表里时返回 `unknown`，不编造。
pub fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0304 => "tls1.3",
        0x0303 => "tls1.2",
        0x0302 => "tls1.1",
        0x0301 => "tls1.0",
        0x0300 => "ssl3.0",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::types::{Confidence, Detection};

    fn det() -> Detection {
        Detection::new(AppId::Tls, Confidence::High, "test")
    }

    #[test]
    fn every_emitted_attr_is_registered_and_typed() {
        let mut d = det();
        d.sni = Some("example.com".to_string());
        d.ja3 = Some("0".repeat(32));
        d.tls_version = Some(0x0303);
        d.method = None;
        d.host = None;
        let attrs = emit(&d);
        assert!(!attrs.is_empty());
        for a in &attrs {
            a.validate().expect("产出属性必须通过真源校验");
        }
    }

    #[test]
    fn unknown_app_emits_no_app_id() {
        // 未识别时**不**产出 APP_ID，否则"已识别占比"会被 unknown 撑满
        let d = Detection::new(AppId::Unknown, Confidence::Low, "test");
        assert!(emit(&d).iter().all(|a| a.id != attributes_gen::ATTR_APP_ID));
    }

    #[test]
    fn missing_sni_emits_no_sni_attr() {
        // 关键语义：不产出 ≠ 产出空串。ECH 流量必须落在这个分支上。
        let d = det();
        assert!(emit(&d)
            .iter()
            .all(|a| a.id != attributes_gen::ATTR_TLS_SNI));
        assert!(emit(&d)
            .iter()
            .all(|a| a.id != attributes_gen::ATTR_SERVER_FQDN));
    }

    #[test]
    fn server_fqdn_covers_both_tls_and_http() {
        let mut tls = det();
        tls.sni = Some("a.example".to_string());
        assert!(emit(&tls)
            .iter()
            .any(|a| a.id == attributes_gen::ATTR_SERVER_FQDN));

        let mut http = Detection::new(AppId::Http, Confidence::High, "test");
        http.host = Some("b.example".to_string());
        assert!(emit(&http)
            .iter()
            .any(|a| a.id == attributes_gen::ATTR_SERVER_FQDN));
    }

    #[test]
    fn unregistered_attr_is_rejected() {
        let a = Attr::new("ATTR_NOT_IN_REGISTRY", AttrType::String, "x");
        assert_eq!(
            a.validate(),
            Err(AttrError::Unregistered("ATTR_NOT_IN_REGISTRY"))
        );
    }

    #[test]
    fn type_mismatch_is_rejected() {
        // ATTR_TLS_SNI 登记为 string，这里谎报成 u16 —— 必须被真源定义挡住
        let a = Attr::new(attributes_gen::ATTR_TLS_SNI, AttrType::U16, "1");
        assert!(matches!(a.validate(), Err(AttrError::TypeMismatch(..))));
    }

    #[test]
    fn tls_version_names_are_stable() {
        assert_eq!(tls_version_name(0x0304), "tls1.3");
        assert_eq!(tls_version_name(0x0303), "tls1.2");
        assert_eq!(tls_version_name(0x9999), "unknown");
    }
}
