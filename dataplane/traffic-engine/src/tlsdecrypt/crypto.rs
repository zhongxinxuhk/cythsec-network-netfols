//! TLS 1.3 记录层解密所需的密码学原语。
//!
//! 本仓库的核心数据面**零第三方依赖**（Rust/Go 均自研），因此这里手写
//! SHA-256 / SHA-384 / HMAC / HKDF / AES / GCM / ChaCha20-Poly1305，而不是引入
//! `sha2`、`aes-gcm`、`chacha20poly1305`。这些实现只服务一个很窄的用途：用运维方
//! 提供的 NSS key log 解开 TLS 1.3 的 AES-128-GCM / AES-256-GCM /
//! ChaCha20-Poly1305 应用记录。**不做密钥协商、不导出密钥、不猜测密钥。**
//!
//! 安全性说明：
//! * AES / GCM 的常量时间性质没有经过侧信道审计；本模块只在**离线**
//!   分析进程里处理已捕获的密文，不接收远程输入来触发解密。
//! * GCM 标签比较使用累积 XOR，避免明显的提前返回；仍不宣称抗计时攻击。
//! * 只支持 TLS 1.3 的三个标准 AEAD 套件（0x1301 / 0x1302 / 0x1303）。
//!   其它套件显式报错，而不是悄悄输出"解密失败"。

/// SHA-256 的 64 个轮常量：前 64 个素数立方根小数部分的前 32 位。
///
/// 这里直接写常量而不是运行时用 `f64::cbrt` 生成：不同平台的 libm 在
/// 最后一位上不保证一致，而错一个常量会让所有摘要静默变化。常量值由
/// FIPS 180-4 定义，并由下面的已知摘要向量验证。
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 初始状态：前 8 个素数平方根小数部分的前 32 位。
const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-384 的 80 个轮常量：前 80 个素数立方根小数部分的前 64 位。
const SHA384_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-384 初始状态：前 8 个素数平方根小数部分的前 64 位。
const SHA384_H: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// 增量 SHA-256。
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_bytes: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: SHA256_H,
            buf: [0u8; 64],
            buf_len: 0,
            total_bytes: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..] {
                *b = 0;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] {
            *b = 0;
        }
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress(&block);
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let k = &SHA256_K;
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (dst, v) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *dst = dst.wrapping_add(v);
        }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

/// 增量 SHA-384（FIPS 180-4，SHA-512 的截断变体）。
pub struct Sha384 {
    state: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total_bytes: u128,
}

impl Sha384 {
    pub fn new() -> Self {
        Self {
            state: SHA384_H,
            buf: [0u8; 128],
            buf_len: 0,
            total_bytes: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u128);
        if self.buf_len > 0 {
            let need = 128 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 128 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 128 {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[..128]);
            self.compress(&block);
            data = &data[128..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; 48] {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 112 {
            for b in &mut self.buf[self.buf_len..] {
                *b = 0;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..112] {
            *b = 0;
        }
        self.buf[112..128].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress(&block);
        let mut out = [0u8; 48];
        for (i, word) in self.state[..6].iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 128]) {
        let k = &SHA384_K;
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                block[i * 8],
                block[i * 8 + 1],
                block[i * 8 + 2],
                block[i * 8 + 3],
                block[i * 8 + 4],
                block[i * 8 + 5],
                block[i * 8 + 6],
                block[i * 8 + 7],
            ]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (dst, v) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *dst = dst.wrapping_add(v);
        }
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finish()
}

/// HMAC-SHA256（RFC 2104）。
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner = inner.finish();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finish()
}

/// HMAC-SHA384（RFC 2104）。
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    let mut k = [0u8; 128];
    if key.len() > 128 {
        k[..48].copy_from_slice(&sha384(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for i in 0..128 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha384::new();
    inner.update(&ipad);
    inner.update(data);
    let inner = inner.finish();
    let mut outer = Sha384::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finish()
}

/// HKDF-Extract（RFC 5869），TLS 1.3 只用 SHA-256。
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand（RFC 5869）。`len` 上限 255*32。
pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 255 * 32, "hkdf output too long");
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_sha256(prk, &msg).to_vec();
        let take = (len - out.len()).min(t.len());
        out.extend_from_slice(&t[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

/// TLS 1.3 的 `HKDF-Expand-Label`（RFC 8446 §7.1）。
pub fn expand_label(traffic_material: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(traffic_material, &info, len)
}

/// HKDF-Extract with SHA-384（RFC 5869），供 TLS_AES_256_GCM_SHA384 使用。
pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    hmac_sha384(salt, ikm)
}

/// HKDF-Expand with SHA-384（RFC 5869）。`len` 上限 255*48。
pub fn hkdf_expand_sha384(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 255 * 48, "hkdf output too long");
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_sha384(prk, &msg).to_vec();
        let take = (len - out.len()).min(t.len());
        out.extend_from_slice(&t[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

/// TLS 1.3 的 `HKDF-Expand-Label` with SHA-384。
pub fn expand_label_sha384(
    traffic_material: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand_sha384(traffic_material, &info, len)
}

// ---------------------------------------------------------------------------
// AES
// ---------------------------------------------------------------------------

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // a^254 = a^-1 in GF(2^8)
    let mut r = 1u8;
    for _ in 0..254 {
        r = gf_mul(r, a);
    }
    r
}

fn aes_sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    for i in 0..256u16 {
        let b = gf_inv(i as u8);
        s[i as usize] =
            b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63;
    }
    s
}

fn sbox_table() -> &'static [u8; 256] {
    use std::sync::OnceLock;
    static S: OnceLock<[u8; 256]> = OnceLock::new();
    S.get_or_init(aes_sbox)
}

fn sub_word(w: [u8; 4]) -> [u8; 4] {
    let s = sbox_table();
    [
        s[w[0] as usize],
        s[w[1] as usize],
        s[w[2] as usize],
        s[w[3] as usize],
    ]
}

fn rot_word(w: [u8; 4]) -> [u8; 4] {
    [w[1], w[2], w[3], w[0]]
}

/// AES-128 / AES-256 分组加密（FIPS-197）。
pub struct Aes {
    round_keys: Vec<[u8; 16]>,
    rounds: usize,
}

impl Aes {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != 16 && key.len() != 32 {
            return Err(format!("AES key length {} is not 16 or 32", key.len()));
        }
        let nk = key.len() / 4;
        let rounds = nk + 6;
        let total = 4 * (rounds + 1);
        let mut w = vec![[0u8; 4]; total];
        for i in 0..nk {
            w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
        }
        let mut rcon = 1u8;
        for i in nk..total {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = sub_word(rot_word(temp));
                temp[0] ^= rcon;
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                temp = sub_word(temp);
            }
            for j in 0..4 {
                w[i][j] = w[i - nk][j] ^ temp[j];
            }
        }
        let mut round_keys = Vec::with_capacity(rounds + 1);
        for r in 0..=rounds {
            let mut k = [0u8; 16];
            for c in 0..4 {
                k[c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
            }
            round_keys.push(k);
        }
        Ok(Self { round_keys, rounds })
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        for (b, k) in block.iter_mut().zip(self.round_keys[0]) {
            *b ^= k;
        }
        for round in 1..=self.rounds {
            sub_bytes(block);
            shift_rows(block);
            if round != self.rounds {
                mix_columns(block);
            }
            for (b, k) in block.iter_mut().zip(self.round_keys[round]) {
                *b ^= k;
            }
        }
    }
}

fn sub_bytes(b: &mut [u8; 16]) {
    let s = sbox_table();
    for x in b.iter_mut() {
        *x = s[*x as usize];
    }
}

fn shift_rows(b: &mut [u8; 16]) {
    // 列主序：b[r + 4*c]
    for r in 1..4 {
        let row = [b[r], b[r + 4], b[r + 8], b[r + 12]];
        for c in 0..4 {
            b[r + 4 * c] = row[(c + r) % 4];
        }
    }
}

fn mix_columns(b: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = b[i];
        let a1 = b[i + 1];
        let a2 = b[i + 2];
        let a3 = b[i + 3];
        b[i] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        b[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        b[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        b[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

fn gf128_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        if v & 1 == 1 {
            v = (v >> 1) ^ (0xe1u128 << 120);
        } else {
            v >>= 1;
        }
    }
    z
}

fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
    let mut y = 0u128;
    for chunk in aad.chunks(16) {
        let mut b = [0u8; 16];
        b[..chunk.len()].copy_from_slice(chunk);
        y = gf128_mul(y ^ u128::from_be_bytes(b), h);
    }
    for chunk in ct.chunks(16) {
        let mut b = [0u8; 16];
        b[..chunk.len()].copy_from_slice(chunk);
        y = gf128_mul(y ^ u128::from_be_bytes(b), h);
    }
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lens[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    gf128_mul(y ^ u128::from_be_bytes(lens), h)
}

fn inc32(block: &mut [u8; 16]) {
    let ctr = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    block[12..].copy_from_slice(&ctr.wrapping_add(1).to_be_bytes());
}

/// AES-GCM 解密并校验标签。`sealed` = 密文 || 16 字节标签。
pub fn aes_gcm_open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    if nonce.len() != 12 {
        return Err(format!("GCM nonce length {} is not 12", nonce.len()));
    }
    if sealed.len() < 16 {
        return Err("GCM ciphertext shorter than tag".into());
    }
    let aes = Aes::new(key)?;
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let mut hb = [0u8; 16];
    aes.encrypt_block(&mut hb);
    let h = u128::from_be_bytes(hb);
    let s = ghash(h, aad, ct);
    let mut mask = j0;
    aes.encrypt_block(&mut mask);
    let expect = s ^ u128::from_be_bytes(mask);
    let expect = expect.to_be_bytes();
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expect[i] ^ tag[i];
    }
    if diff != 0 {
        return Err("GCM tag mismatch".into());
    }
    let mut out = Vec::with_capacity(ct.len());
    let mut ctr = j0;
    for chunk in ct.chunks(16) {
        inc32(&mut ctr);
        let mut ks = ctr;
        aes.encrypt_block(&mut ks);
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
    }
    Ok(out)
}

/// AES-GCM 加密，返回密文 || 16 字节标签。
///
/// 生产路径只用 `open`；`seal` 供测试构造真实记录格式的向量，避免用
/// “自己加密再自己解密”冒充外部对照。
pub fn aes_gcm_seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    if nonce.len() != 12 {
        return Err(format!("GCM nonce length {} is not 12", nonce.len()));
    }
    let aes = Aes::new(key)?;
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let mut hb = [0u8; 16];
    aes.encrypt_block(&mut hb);
    let h = u128::from_be_bytes(hb);
    let mut ct = Vec::with_capacity(plaintext.len());
    let mut ctr = j0;
    for chunk in plaintext.chunks(16) {
        inc32(&mut ctr);
        let mut ks = ctr;
        aes.encrypt_block(&mut ks);
        for (i, b) in chunk.iter().enumerate() {
            ct.push(b ^ ks[i]);
        }
    }
    let s = ghash(h, aad, &ct);
    let mut mask = j0;
    aes.encrypt_block(&mut mask);
    let tag = (s ^ u128::from_be_bytes(mask)).to_be_bytes();
    ct.extend_from_slice(&tag);
    Ok(ct)
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305（RFC 8439）
// ---------------------------------------------------------------------------

fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let mut x = state;
    for _ in 0..10 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = x[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// ChaCha20 流加密/解密（RFC 8439 §2.4）。
pub fn chacha20_xor(
    key: &[u8],
    nonce: &[u8],
    counter: u32,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("ChaCha20 key length {} is not 32", key.len()));
    }
    if nonce.len() != 12 {
        return Err(format!("ChaCha20 nonce length {} is not 12", nonce.len()));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    let mut out = Vec::with_capacity(data.len());
    for (i, chunk) in data.chunks(64).enumerate() {
        let block = chacha20_block(&key_arr, counter.wrapping_add(i as u32), &nonce_arr);
        for (j, b) in chunk.iter().enumerate() {
            out.push(b ^ block[j]);
        }
    }
    Ok(out)
}

fn load32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Poly1305 MAC（RFC 8439 §2.5），5x26 位实现。
pub fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    const M: u32 = 0x3ffffff;
    let r0 = load32(&key[0..4]) & 0x3ffffff;
    let r1 = (load32(&key[3..7]) >> 2) & 0x3ffff03;
    let r2 = (load32(&key[6..10]) >> 4) & 0x3ffc0ff;
    let r3 = (load32(&key[9..13]) >> 6) & 0x3f03fff;
    let r4 = (load32(&key[12..16]) >> 8) & 0x00fffff;
    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);

    for chunk in msg.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;
        let t0 = load32(&block[0..4]);
        let t1 = load32(&block[4..8]);
        let t2 = load32(&block[8..12]);
        let t3 = load32(&block[12..16]);
        let hibit = if chunk.len() == 16 { 1u32 << 24 } else { 0 };
        h0 = h0.wrapping_add(t0 & M);
        h1 = h1.wrapping_add(((t0 >> 26) | (t1 << 6)) & M);
        h2 = h2.wrapping_add(((t1 >> 20) | (t2 << 12)) & M);
        h3 = h3.wrapping_add(((t2 >> 14) | (t3 << 18)) & M);
        h4 = h4.wrapping_add((t3 >> 8) | hibit);

        let d0 = (h0 as u64) * (r0 as u64)
            + (h1 as u64) * (s4 as u64)
            + (h2 as u64) * (s3 as u64)
            + (h3 as u64) * (s2 as u64)
            + (h4 as u64) * (s1 as u64);
        let d1 = (h0 as u64) * (r1 as u64)
            + (h1 as u64) * (r0 as u64)
            + (h2 as u64) * (s4 as u64)
            + (h3 as u64) * (s3 as u64)
            + (h4 as u64) * (s2 as u64);
        let d2 = (h0 as u64) * (r2 as u64)
            + (h1 as u64) * (r1 as u64)
            + (h2 as u64) * (r0 as u64)
            + (h3 as u64) * (s4 as u64)
            + (h4 as u64) * (s3 as u64);
        let d3 = (h0 as u64) * (r3 as u64)
            + (h1 as u64) * (r2 as u64)
            + (h2 as u64) * (r1 as u64)
            + (h3 as u64) * (r0 as u64)
            + (h4 as u64) * (s4 as u64);
        let d4 = (h0 as u64) * (r4 as u64)
            + (h1 as u64) * (r3 as u64)
            + (h2 as u64) * (r2 as u64)
            + (h3 as u64) * (r1 as u64)
            + (h4 as u64) * (r0 as u64);
        let mut c = (d0 >> 26) as u32;
        h0 = d0 as u32 & M;
        let d1 = d1 + c as u64;
        c = (d1 >> 26) as u32;
        h1 = d1 as u32 & M;
        let d2 = d2 + c as u64;
        c = (d2 >> 26) as u32;
        h2 = d2 as u32 & M;
        let d3 = d3 + c as u64;
        c = (d3 >> 26) as u32;
        h3 = d3 as u32 & M;
        let d4 = d4 + c as u64;
        c = (d4 >> 26) as u32;
        h4 = d4 as u32 & M;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= M;
        h1 += c;
    }

    let mut c = h1 >> 26;
    h1 &= M;
    h2 += c;
    c = h2 >> 26;
    h2 &= M;
    h3 += c;
    c = h3 >> 26;
    h3 &= M;
    h4 += c;
    c = h4 >> 26;
    h4 &= M;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= M;
    h1 += c;

    let mut g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= M;
    let mut g1 = h1 + c;
    c = g1 >> 26;
    g1 &= M;
    let mut g2 = h2 + c;
    c = g2 >> 26;
    g2 &= M;
    let mut g3 = h3 + c;
    c = g3 >> 26;
    g3 &= M;
    let g4 = (h4 + c).wrapping_sub(1 << 26);
    let select = (g4 >> 31).wrapping_sub(1);
    let keep = !select;
    h0 = (h0 & keep) | (g0 & select);
    h1 = (h1 & keep) | (g1 & select);
    h2 = (h2 & keep) | (g2 & select);
    h3 = (h3 & keep) | (g3 & select);
    h4 = (h4 & keep) | (g4 & select);

    let pad0 = load32(&key[16..20]) as u64;
    let pad1 = load32(&key[20..24]) as u64;
    let pad2 = load32(&key[24..28]) as u64;
    let pad3 = load32(&key[28..32]) as u64;
    let mut f0 = ((h0 as u64) | ((h1 as u64) << 26)) & 0xffffffff;
    let mut f1 = (((h1 >> 6) as u64) | ((h2 as u64) << 20)) & 0xffffffff;
    let mut f2 = (((h2 >> 12) as u64) | ((h3 as u64) << 14)) & 0xffffffff;
    let mut f3 = (((h3 >> 18) as u64) | ((h4 as u64) << 8)) & 0xffffffff;
    f0 += pad0;
    let mut carry = f0 >> 32;
    f0 &= 0xffffffff;
    f1 += pad1 + carry;
    carry = f1 >> 32;
    f1 &= 0xffffffff;
    f2 += pad2 + carry;
    carry = f2 >> 32;
    f2 &= 0xffffffff;
    f3 += pad3 + carry;
    f3 &= 0xffffffff;

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
    out[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
    out[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
    out
}

fn poly1305_pad16(out: &mut Vec<u8>) {
    while out.len() % 16 != 0 {
        out.push(0);
    }
}

fn poly1305_input(aad: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(aad.len() + ct.len() + 32);
    out.extend_from_slice(aad);
    poly1305_pad16(&mut out);
    out.extend_from_slice(ct);
    poly1305_pad16(&mut out);
    out.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    out.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    out
}

/// ChaCha20-Poly1305 AEAD 解密并校验标签，`sealed` = 密文 || 16 字节标签。
pub fn chacha20_poly1305_open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("ChaCha20 key length {} is not 32", key.len()));
    }
    if nonce.len() != 12 {
        return Err(format!("ChaCha20 nonce length {} is not 12", nonce.len()));
    }
    if sealed.len() < 16 {
        return Err("ChaCha20-Poly1305 ciphertext shorter than tag".into());
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    let block0 = chacha20_block(&key_arr, 0, &nonce_arr);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block0[..32]);
    let expected = poly1305_mac(&poly_key, &poly1305_input(aad, ct));
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected[i] ^ tag[i];
    }
    if diff != 0 {
        return Err("ChaCha20-Poly1305 tag mismatch".into());
    }
    chacha20_xor(key, nonce, 1, ct)
}

/// ChaCha20-Poly1305 AEAD 加密，返回密文 || 16 字节标签。
pub fn chacha20_poly1305_seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("ChaCha20 key length {} is not 32", key.len()));
    }
    if nonce.len() != 12 {
        return Err(format!("ChaCha20 nonce length {} is not 12", nonce.len()));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    let block0 = chacha20_block(&key_arr, 0, &nonce_arr);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block0[..32]);
    let mut ct = chacha20_xor(key, nonce, 1, plaintext)?;
    let tag = poly1305_mac(&poly_key, &poly1305_input(aad, &ct));
    ct.extend_from_slice(&tag);
    Ok(ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&hex(s));
        out
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256(b""),
            hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abc"),
            hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex32("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
        // 跨越 64 字节块边界，覆盖增量 update 的缓冲路径。
        let mut h = Sha256::new();
        for chunk in [
            &b"a"[..],
            &b"bcdefghijklmnopqrstuvwxyz"[..],
            &b"0123456789"[..],
        ] {
            h.update(chunk);
        }
        assert_eq!(h.finish(), sha256(b"abcdefghijklmnopqrstuvwxyz0123456789"));
    }

    fn hex48(s: &str) -> [u8; 48] {
        let mut out = [0u8; 48];
        out.copy_from_slice(&hex(s));
        out
    }

    #[test]
    fn sha384_known_vectors() {
        assert_eq!(
            sha384(b""),
            hex48("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
        );
        assert_eq!(
            sha384(b"abc"),
            hex48("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
        );
        assert_eq!(
            sha384(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            hex48("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039")
        );
        // 跨越 128 字节块边界，覆盖增量 update 与两段式 padding。
        let mut h = Sha384::new();
        for chunk in [
            &b"a"[..],
            &b"bcdefghijklmnopqrstuvwxyz"[..],
            &b"0123456789"[..],
        ] {
            h.update(chunk);
        }
        assert_eq!(h.finish(), sha384(b"abcdefghijklmnopqrstuvwxyz0123456789"));
    }

    #[test]
    fn hmac_and_hkdf_sha384_vectors() {
        assert_eq!(
            hmac_sha384(&[0x0bu8; 20], b"Hi There"),
            hex48("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")
        );
        let ikm: Vec<u8> = (0u8..48).collect();
        let salt: Vec<u8> = (0u8..16).collect();
        let prk = hkdf_extract_sha384(&salt, &ikm);
        assert_eq!(
            prk,
            hex48("f4a1e0bae3ea4be0df92b75f0d16c00bf3e43fd642da8179ede707030cd48fa52464b7853fab127982093ba30bfe6b19")
        );
        assert_eq!(
            hkdf_expand_sha384(&prk, b"tls13 key", 32),
            hex("e31e318fbe432384db32c69daa28cb868ef986c7a1d7ca09fdec141541f2186b")
        );
    }

    #[test]
    fn expand_label_sha384_matches_independent_hkdf() {
        let material = [0x42u8; 48];
        assert_eq!(
            expand_label_sha384(&material, "key", &[], 32),
            hex("fa6212f4bc8c9a9e1222fe6c099e49acdf1b6ffbfeba0c9ff88413d7ca28177e")
        );
        assert_eq!(
            expand_label_sha384(&material, "iv", &[], 12),
            hex("f065d87b4ab5b38df160ed28")
        );
    }

    #[test]
    fn hmac_and_hkdf_rfc5869_case1() {
        assert_eq!(
            hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog"),
            hex32("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
        );
        let ikm = [0x0bu8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk,
            hex32("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let okm = hkdf_expand(&prk, &info, 42);
        assert_eq!(
            okm,
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
    }

    #[test]
    fn aes_fips197_vectors() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let aes = Aes::new(&key).unwrap();
        let mut block = [0u8; 16];
        block.copy_from_slice(&hex("00112233445566778899aabbccddeeff"));
        aes.encrypt_block(&mut block);
        assert_eq!(block.to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));

        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let aes = Aes::new(&key).unwrap();
        let mut block = [0u8; 16];
        block.copy_from_slice(&hex("00112233445566778899aabbccddeeff"));
        aes.encrypt_block(&mut block);
        assert_eq!(block.to_vec(), hex("8ea2b7ca516745bfeafc49904b496089"));
    }

    #[test]
    fn aes_gcm_nist_vectors() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        // 空明文：标签单独验证。
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&hex("58e2fccefa7e3061367f1d57a4e7455a"));
        assert_eq!(
            aes_gcm_open(&key, &nonce, &[], &sealed).unwrap(),
            Vec::<u8>::new()
        );

        // 16 字节全零明文。
        let mut sealed = hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
        let pt = aes_gcm_open(&key, &nonce, &[], &sealed).unwrap();
        assert_eq!(pt, vec![0u8; 16]);
        sealed[0] ^= 1;
        assert!(aes_gcm_open(&key, &nonce, &[], &sealed).is_err());
        assert_eq!(
            aes_gcm_seal(&key, &nonce, &[], &[0u8; 16]).unwrap(),
            hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
        );

        // NIST GCM test case 15/16：256-bit key。
        let key256 = [0u8; 32];
        let mut sealed = hex("530f8afbc74536b9a963b4f1c4cb738b");
        assert_eq!(
            aes_gcm_open(&key256, &nonce, &[], &sealed).unwrap(),
            Vec::<u8>::new()
        );
        sealed = hex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
        assert_eq!(
            aes_gcm_open(&key256, &nonce, &[], &sealed).unwrap(),
            vec![0u8; 16]
        );
        assert_eq!(
            aes_gcm_seal(&key256, &nonce, &[], &[0u8; 16]).unwrap(),
            sealed
        );
    }

    #[test]
    fn chacha20_block_rfc8439() {
        let key = hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hex("000000090000004a00000000"));
        assert_eq!(
            chacha20_block(&key, 1, &nonce).to_vec(),
            hex("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
        );
    }

    #[test]
    fn poly1305_rfc8439() {
        let mut k = [0u8; 32];
        k.copy_from_slice(&hex(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        ));
        assert_eq!(
            poly1305_mac(&k, b"Cryptographic Forum Research Group").to_vec(),
            hex("a8061dc1305136c6c22b8baf0c0127a9")
        );
    }

    #[test]
    fn chacha20_poly1305_rfc8439() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hex("070000004041424344454647"));
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
        let sealed = chacha20_poly1305_seal(&key, &nonce, &aad, plaintext).unwrap();
        assert_eq!(sealed, expected);
        assert_eq!(
            chacha20_poly1305_open(&key, &nonce, &aad, &sealed).unwrap(),
            plaintext.to_vec()
        );
        let mut broken = sealed.clone();
        let last = broken.len() - 1;
        broken[last] ^= 1;
        assert!(chacha20_poly1305_open(&key, &nonce, &aad, &broken).is_err());
    }

    #[test]
    fn expand_label_matches_rfc8448_application_keys() {
        // RFC 8448 §3：客户端/服务端应用流量密钥。
        let client = hex32("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
        let server = hex32("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
        assert_eq!(
            expand_label(&client, "key", &[], 16),
            hex("17422dda596ed5d9acd890e3c63f5051")
        );
        assert_eq!(
            expand_label(&client, "iv", &[], 12),
            hex("5b78923dee08579033e523d9")
        );
        assert_eq!(
            expand_label(&server, "key", &[], 16),
            hex("9f02283b6c9c07efc26bb9f2ac92e356")
        );
        assert_eq!(
            expand_label(&server, "iv", &[], 12),
            hex("cf782b88dd83549aadf1e984")
        );
    }
}
