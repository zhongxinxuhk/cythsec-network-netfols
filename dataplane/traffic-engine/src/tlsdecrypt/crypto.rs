//! TLS 1.3 记录层解密所需的密码学原语。
//!
//! 本仓库的核心数据面**零第三方依赖**（Rust/Go 均自研），因此这里手写
//! SHA-256 / HMAC / HKDF / AES / GCM，而不是引入 `sha2`、`aes-gcm`。
//! 这些实现只服务一个很窄的用途：用运维方提供的 NSS key log 解开
//! TLS 1.3 的 AES-128-GCM 应用记录。**不做密钥协商、不导出密钥、不猜测密钥。**
//!
//! 安全性说明：
//! * AES / GCM 的常量时间性质没有经过侧信道审计；本模块只在**离线**
//!   分析进程里处理已捕获的密文，不接收远程输入来触发解密。
//! * GCM 标签比较使用累积 XOR，避免明显的提前返回；仍不宣称抗计时攻击。
//! * 只支持 TLS_AES_128_GCM_SHA256（0x1301）。其它套件显式报错，
//!   而不是悄悄输出"解密失败"。

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
