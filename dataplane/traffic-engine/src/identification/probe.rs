//! A planning boundary only: this module has no socket/process/network execution API.
use super::lookup;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol_id: String,
}
#[derive(Debug, Clone)]
pub struct Authorization {
    pub id: String,
    pub expires_us: u64,
    pub allowed: Vec<Target>,
    pub total_budget: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePlan {
    pub authorization_id: String,
    pub target: Target,
    pub expires_us: u64,
    pub timeout_ms: u16,
    pub max_packets: u8,
    pub executed: bool,
}
pub struct ProbePlanner {
    authorization: Authorization,
    used: u32,
    seen: Vec<Target>,
}
impl ProbePlanner {
    pub fn new(authorization: Authorization) -> Self {
        Self {
            authorization,
            used: 0,
            seen: Vec::new(),
        }
    }
    pub fn plan(&mut self, target: Target, now_us: u64) -> Result<ProbePlan, &'static str> {
        let a = &self.authorization;
        if a.id.is_empty() || a.id.len() > 128 || a.expires_us <= now_us {
            return Err("missing or expired authorization");
        }
        if target.ip.is_unspecified()
            || target.ip.is_multicast()
            || target.port == 0
            || lookup(&target.protocol_id).is_none()
        {
            return Err("invalid exact target");
        }
        if !a.allowed.contains(&target) {
            return Err("target/protocol outside exact allowlist");
        }
        if self.used >= a.total_budget || self.seen.contains(&target) {
            return Err("global or per-target budget exhausted");
        }
        self.used += 1;
        self.seen.push(target.clone());
        Ok(ProbePlan {
            authorization_id: a.id.clone(),
            target,
            expires_us: a.expires_us,
            timeout_ms: 3000,
            max_packets: 3,
            executed: false,
        })
    }
}
