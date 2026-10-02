// testjson.rs —— 测试用的最小 JSON 解析器（仅 `#[cfg(test)]` 下编译）。
//
// 为什么单独成模块而不是各测试文件里各写一份：
//   向量驱动测试要读生成器产出的 expected.json（dpi、reassembly 都要读）。
//   各写一份的话，两份解析器的行为差异会变成"某些字段被静默读成 null"，
//   表现为测试跳过断言但仍报绿 —— 这是本项目反复踩过的假绿灯。
//   共用一份，解析行为只有一个来源。
//
// 只解析生成器产出的那份 JSON，够用即可。之所以不引 serde：
// 本包刻意零第三方依赖（见 Cargo.toml），为这点用途打破它不值得。

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Num(n) => Some(*n as i64),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }
}

pub struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> JsonParser<'a> {
    pub fn new(s: &'a str) -> Self {
        Self {
            b: s.as_bytes(),
            i: 0,
        }
    }
    pub fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    pub fn value(&mut self) -> Json {
        self.ws();
        match self.b[self.i] {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Json::Str(self.string()),
            b't' => {
                self.i += 4;
                Json::Bool(true)
            }
            b'f' => {
                self.i += 5;
                Json::Bool(false)
            }
            b'n' => {
                self.i += 4;
                Json::Null
            }
            _ => self.number(),
        }
    }
    pub fn object(&mut self) -> Json {
        self.i += 1; // {
        let mut out = Vec::new();
        loop {
            self.ws();
            if self.b[self.i] == b'}' {
                self.i += 1;
                return Json::Obj(out);
            }
            if self.b[self.i] == b',' {
                self.i += 1;
                continue;
            }
            let k = self.string();
            self.ws();
            self.i += 1; // :
            let v = self.value();
            out.push((k, v));
        }
    }
    pub fn array(&mut self) -> Json {
        self.i += 1; // [
        let mut out = Vec::new();
        loop {
            self.ws();
            if self.b[self.i] == b']' {
                self.i += 1;
                return Json::Arr(out);
            }
            if self.b[self.i] == b',' {
                self.i += 1;
                continue;
            }
            out.push(self.value());
        }
    }
    pub fn string(&mut self) -> String {
        self.i += 1; // 开引号
        let mut out = Vec::new();
        loop {
            let c = self.b[self.i];
            match c {
                b'"' => {
                    self.i += 1;
                    return String::from_utf8(out).expect("JSON 字符串必须是合法 UTF-8");
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.b[self.i];
                    match e {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            // \uXXXX：只处理 BMP 内的码点，够解析生成器的 ASCII 内容
                            let hex = std::str::from_utf8(&self.b[self.i + 1..self.i + 5])
                                .expect("非法 \\u 转义");
                            let cp = u32::from_str_radix(hex, 16).expect("非法 \\u 码点");
                            self.i += 4;
                            match char::from_u32(cp) {
                                Some(ch) => out.extend_from_slice(ch.to_string().as_bytes()),
                                None => out.push(b'?'),
                            }
                        }
                        other => out.push(other),
                    }
                    self.i += 1;
                }
                _ => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }
    pub fn number(&mut self) -> Json {
        let start = self.i;
        while self.i < self.b.len()
            && matches!(
                self.b[self.i],
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'
            )
        {
            self.i += 1;
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).expect("非法数字");
        Json::Num(s.parse::<f64>().expect("非法数字"))
    }
}
