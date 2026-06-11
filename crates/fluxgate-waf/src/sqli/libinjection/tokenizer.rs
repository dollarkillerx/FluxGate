//! Tokenizer — port of the `parse_*` functions and `libinjection_sqli_tokenize`
//! from `libinjection_sqli.c`.
//!
//! A literal port: the manual case-insensitive byte compares mirror
//! libinjection's `cstrcasecmp`, the distinct-but-identical `if`/`else` arms
//! (e.g. the three comment branches of `parse_dash`, the float-suffix arms of
//! `parse_number`) mirror the C cascade, and `!(have_e && !have_exp)` is a
//! verbatim port of the C condition. These Clippy style lints are allowed
//! module-wide to keep the 1:1 correspondence with the reference engine.
#![allow(
    clippy::if_same_then_else,
    clippy::manual_ignore_case_cmp,
    clippy::manual_range_contains, // `ch < 33 || ch > 127` mirrors the C signed-char test
    clippy::nonminimal_bool
)]

use super::*;

/// Maximum number of folded tokens (`LIBINJECTION_SQLI_MAX_TOKENS`).
pub(crate) const MAX_TOKENS: usize = 5;
/// Token value buffer size (`LIBINJECTION_SQLI_TOKEN_SIZE` == `sizeof val`).
///
/// In C this is `sizeof(((stoken_t*)0)->val)`, i.e. the 32-byte `val` array.
pub(crate) const TOKEN_SIZE: usize = 32;

/// A single token (`stoken_t`).
#[derive(Clone)]
pub(crate) struct Token {
    pub type_: u8,
    pub pos: usize,
    /// Logical length of the value (may exceed [`TOKEN_SIZE`] conceptually, but
    /// the stored bytes are capped at `TOKEN_SIZE - 1`, matching `st_assign`).
    pub len: usize,
    pub val: [u8; TOKEN_SIZE],
    pub str_open: u8,
    pub str_close: u8,
    pub count: u8,
}

impl Token {
    fn new() -> Self {
        Token {
            type_: TYPE_NONE,
            pos: 0,
            len: 0,
            val: [0u8; TOKEN_SIZE],
            str_open: CHAR_NULL,
            str_close: CHAR_NULL,
            count: 0,
        }
    }

    fn clear(&mut self) {
        *self = Token::new();
    }

    /// The stored value bytes (`val[..len_capped]`).
    pub(crate) fn value(&self) -> &[u8] {
        let n = self.len.min(TOKEN_SIZE - 1);
        &self.val[..n]
    }

    /// First value byte, or NUL (`val[0]`).
    pub(crate) fn val_first(&self) -> u8 {
        self.val[0]
    }

    /// `st_assign_char`.
    fn assign_char(&mut self, stype: u8, pos: usize, value: u8) {
        self.type_ = stype;
        self.pos = pos;
        self.len = 1;
        self.val = [0u8; TOKEN_SIZE];
        self.val[0] = value;
        self.val[1] = CHAR_NULL;
    }

    /// `st_assign` — copies up to `TOKEN_SIZE - 1` bytes of `value`.
    fn assign(&mut self, stype: u8, pos: usize, len: usize, value: &[u8]) {
        let last = if len < TOKEN_SIZE {
            len
        } else {
            TOKEN_SIZE - 1
        };
        self.type_ = stype;
        self.pos = pos;
        self.len = last;
        self.val = [0u8; TOKEN_SIZE];
        self.val[..last].copy_from_slice(&value[..last]);
        self.val[last] = CHAR_NULL;
    }

    fn is_arithmetic_op(&self) -> bool {
        let ch = self.val[0];
        self.type_ == TYPE_OPERATOR
            && self.len == 1
            && matches!(ch, b'*' | b'/' | b'-' | b'+' | b'%')
    }

    /// `st_is_unary_op`.
    pub(crate) fn is_unary_op(&self) -> bool {
        if self.type_ != TYPE_OPERATOR {
            return false;
        }
        match self.len {
            1 => matches!(self.val[0], b'+' | b'-' | b'!' | b'~'),
            2 => self.val[0] == b'!' && self.val[1] == b'!',
            3 => {
                self.val[0].to_ascii_uppercase() == b'N'
                    && self.val[1].to_ascii_uppercase() == b'O'
                    && self.val[2].to_ascii_uppercase() == b'T'
            }
            _ => false,
        }
    }
}

/// Parser state (`struct libinjection_sqli_state`).
pub(crate) struct State {
    pub input: Vec<u8>,
    pub flags: u32,
    pub pos: usize,
    pub tokenvec: Vec<Token>,
    /// Index into `tokenvec` that the next tokenize writes to (`sf->current`).
    pub current: usize,
    pub stats_comment_ddx: u32,
    pub stats_comment_hash: u32,
    pub stats_tokens: u32,
    pub stats_folds: u32,
    // Matches C's `char fingerprint[8]` (libinjection_sqli.h). It must hold up to
    // 7 token types + a NUL: the `{`-bareword EVIL fold case returns `left + 2`
    // (up to 7) *bypassing* the MAX_TOKENS cap, so a smaller buffer would panic on
    // `fp[tlen] = NUL` for crafted input like `a a a a {` followed by a backtick.
    pub fingerprint_buf: [u8; MAX_TOKENS + 3],
    pub fingerprint_len: usize,
}

impl State {
    pub(crate) fn new(input: &[u8]) -> Self {
        // tokenvec needs MAX_TOKENS + slack: the fold loop indexes up to
        // tokenvec[MAX_TOKENS] (the 6th slot) when grabbing a look-ahead token.
        State {
            input: input.to_vec(),
            flags: FLAG_QUOTE_NONE | FLAG_SQL_ANSI,
            pos: 0,
            tokenvec: (0..MAX_TOKENS + 2).map(|_| Token::new()).collect(),
            current: 0,
            stats_comment_ddx: 0,
            stats_comment_hash: 0,
            stats_tokens: 0,
            stats_folds: 0,
            fingerprint_buf: [0u8; MAX_TOKENS + 3],
            fingerprint_len: 0,
        }
    }

    /// `libinjection_sqli_reset` — re-init keeping `input`, set `flags`.
    pub(crate) fn reset(&mut self, mut flags: u32) {
        if flags == 0 {
            flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI;
        }
        self.flags = flags;
        self.pos = 0;
        self.current = 0;
        self.stats_comment_ddx = 0;
        self.stats_comment_hash = 0;
        self.stats_tokens = 0;
        self.stats_folds = 0;
        for t in &mut self.tokenvec {
            t.clear();
        }
        self.fingerprint_buf = [0u8; MAX_TOKENS + 3];
        self.fingerprint_len = 0;
    }

    pub(crate) fn fingerprint(&self) -> &str {
        // fingerprint bytes are all printable ASCII token-type chars.
        std::str::from_utf8(&self.fingerprint_buf[..self.fingerprint_len]).unwrap_or("")
    }

    /// Snapshot of the current token (for oracle test printing).
    pub(crate) fn current_token(&self) -> Token {
        self.tokenvec[self.current].clone()
    }
}

// ---------------------------------------------------------------------------
// Low-level helpers (memchr, strspn, whitespace classification).
// ---------------------------------------------------------------------------

#[inline]
fn is_white(ch: u8) -> bool {
    // " \t\n\v\f\r\240\000"
    matches!(ch, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | 0xa0 | 0x00)
}

/// `memchr` over a sub-slice; returns absolute index from `start_of_input`.
fn memchr_from(cs: &[u8], start: usize, ch: u8) -> Option<usize> {
    cs[start..].iter().position(|&b| b == ch).map(|p| start + p)
}

/// `memchr2`: find two consecutive chars `c0 c1`. Returns absolute index.
fn memchr2(cs: &[u8], start: usize, end: usize, c0: u8, c1: u8) -> Option<usize> {
    if end <= start || (end - start) < 2 {
        return None;
    }
    let mut cur = start;
    while cur + 1 < end {
        if cs[cur] == c0 && cs[cur + 1] == c1 {
            return Some(cur);
        }
        cur += 1;
    }
    None
}

/// length of leading run of bytes that are in `accept`.
fn strlenspn(s: &[u8], accept: &[u8]) -> usize {
    let mut i = 0;
    while i < s.len() {
        // C uses `strchr(accept, s[i])`, which matches the NUL terminator of
        // `accept` — so a NUL byte tests as a member of EVERY set. Replicate that
        // quirk (else `$\0` mis-parses vs the C reference; caught by difftest).
        if s[i] != 0 && !accept.contains(&s[i]) {
            return i;
        }
        i += 1;
    }
    s.len()
}

/// length of leading run of bytes that are NOT in `accept`.
fn strlencspn(s: &[u8], accept: &[u8]) -> usize {
    let mut i = 0;
    while i < s.len() {
        // `strchr(accept, s[i]) != NULL` is also true for a NUL byte (it matches
        // `accept`'s terminator), so NUL stops the complement-span. Mirror the C.
        if s[i] == 0 || accept.contains(&s[i]) {
            return i;
        }
        i += 1;
    }
    s.len()
}

fn flag2delim(flags: u32) -> u8 {
    if flags & FLAG_QUOTE_SINGLE != 0 {
        CHAR_SINGLE
    } else if flags & FLAG_QUOTE_DOUBLE != 0 {
        CHAR_DOUBLE
    } else {
        CHAR_NULL
    }
}

/// `is_backslash_escaped(end, start)` — number of trailing backslashes before
/// (and including) `end` is odd. `end`/`start` are absolute indices; the run is
/// scanned downwards from `end` to `start`.
fn is_backslash_escaped(cs: &[u8], end: usize, start: usize) -> bool {
    // C scans ptr from end down while *ptr == '\\', stopping below `start`.
    // `end` may be `usize::MAX`-ish only when qpos == cs+pos+offset; callers
    // guard with qpos-1 only when qpos > start, but to be safe handle the
    // empty range.
    if end < start {
        return false;
    }
    let mut ptr = end as isize;
    let lo = start as isize;
    while ptr >= lo {
        if cs[ptr as usize] != b'\\' {
            break;
        }
        ptr -= 1;
    }
    ((end as isize - ptr) & 1) == 1
}

// ---------------------------------------------------------------------------
// String parsing core.
// ---------------------------------------------------------------------------

/// `parse_string_core`. Writes into `tok`; returns new absolute position.
fn parse_string_core(
    cs: &[u8],
    len: usize,
    pos: usize,
    tok: &mut Token,
    delim: u8,
    offset: usize,
) -> usize {
    let mut qpos = memchr_from(cs, pos + offset, delim).filter(|&p| p < len);

    if offset > 0 {
        tok.str_open = delim;
    } else {
        tok.str_open = CHAR_NULL;
    }

    loop {
        match qpos {
            None => {
                tok.assign(
                    TYPE_STRING,
                    pos + offset,
                    len - pos - offset,
                    &cs[pos + offset..],
                );
                tok.str_close = CHAR_NULL;
                return len;
            }
            Some(q) => {
                if q > pos + offset && is_backslash_escaped(cs, q - 1, pos + offset) {
                    qpos = memchr_from(cs, q + 1, delim).filter(|&p| p < len);
                    continue;
                } else if q + 1 < len && cs[q + 1] == cs[q] {
                    // is_double_delim_escaped
                    qpos = memchr_from(cs, q + 2, delim).filter(|&p| p < len);
                    continue;
                } else {
                    tok.assign(
                        TYPE_STRING,
                        pos + offset,
                        q - (pos + offset),
                        &cs[pos + offset..],
                    );
                    tok.str_close = delim;
                    return q + 1;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Individual parse_* functions. Each takes &mut State and returns new pos.
// They write into `state.tokenvec[state.current]`.
// ---------------------------------------------------------------------------

macro_rules! cur {
    ($state:expr) => {
        $state.tokenvec[$state.current]
    };
}

fn parse_white(state: &mut State) -> usize {
    state.pos + 1
}

fn parse_operator1(state: &mut State) -> usize {
    let pos = state.pos;
    let ch = state.input[pos];
    cur!(state).assign_char(TYPE_OPERATOR, pos, ch);
    pos + 1
}

fn parse_other(state: &mut State) -> usize {
    let pos = state.pos;
    let ch = state.input[pos];
    cur!(state).assign_char(TYPE_UNKNOWN, pos, ch);
    pos + 1
}

fn parse_char(state: &mut State) -> usize {
    let pos = state.pos;
    let ch = state.input[pos];
    cur!(state).assign_char(ch, pos, ch);
    pos + 1
}

fn parse_eol_comment(state: &mut State) -> usize {
    let cs = &state.input;
    let slen = cs.len();
    let pos = state.pos;
    match memchr_from(cs, pos, b'\n') {
        None => {
            let val = cs[pos..slen].to_vec();
            cur!(state).assign(TYPE_COMMENT, pos, slen - pos, &val);
            slen
        }
        Some(endpos) => {
            let val = cs[pos..endpos].to_vec();
            cur!(state).assign(TYPE_COMMENT, pos, endpos - pos, &val);
            endpos + 1
        }
    }
}

fn parse_hash(state: &mut State) -> usize {
    state.stats_comment_hash += 1;
    if state.flags & FLAG_SQL_MYSQL != 0 {
        state.stats_comment_hash += 1;
        parse_eol_comment(state)
    } else {
        let pos = state.pos;
        cur!(state).assign_char(TYPE_OPERATOR, pos, b'#');
        pos + 1
    }
}

fn parse_dash(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let cs = &state.input;
    if pos + 2 < slen && cs[pos + 1] == b'-' && is_white(cs[pos + 2]) {
        parse_eol_comment(state)
    } else if pos + 2 == slen && cs[pos + 1] == b'-' {
        parse_eol_comment(state)
    } else if pos + 1 < slen && cs[pos + 1] == b'-' && (state.flags & FLAG_SQL_ANSI != 0) {
        state.stats_comment_ddx += 1;
        parse_eol_comment(state)
    } else {
        cur!(state).assign_char(TYPE_OPERATOR, pos, b'-');
        pos + 1
    }
}

fn is_mysql_comment(cs: &[u8], len: usize, pos: usize) -> bool {
    if pos + 2 >= len {
        return false;
    }
    cs[pos + 2] == b'!'
}

fn parse_slash(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let mut ctype = TYPE_COMMENT;
    let pos1 = pos + 1;
    if pos1 == slen || state.input[pos1] != b'*' {
        return parse_operator1(state);
    }

    let cs = &state.input;
    // ptr = memchr2(cur+2, slen-(pos+2), '*','/')
    let ptr = memchr2(cs, pos + 2, slen, b'*', b'/');
    let clen = match ptr {
        None => slen - pos,
        Some(p) => p + 2 - pos,
    };

    // nested comment check + mysql conditional comment
    if let Some(p) = ptr {
        // memchr2(cur+2, ptr-(cur+1), '/','*')  -> search range [pos+2, p+1)
        if memchr2(cs, pos + 2, p + 1, b'/', b'*').is_some() {
            ctype = TYPE_EVIL;
        }
    }
    if is_mysql_comment(cs, slen, pos) {
        ctype = TYPE_EVIL;
    }

    let val = cs[pos..pos + clen].to_vec();
    cur!(state).assign(ctype, pos, clen, &val);
    pos + clen
}

fn parse_backslash(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let cs = &state.input;
    if pos + 1 < slen && cs[pos + 1] == b'N' {
        let val = cs[pos..pos + 2].to_vec();
        cur!(state).assign(TYPE_NUMBER, pos, 2, &val);
        pos + 2
    } else {
        let ch = cs[pos];
        cur!(state).assign_char(TYPE_BACKSLASH, pos, ch);
        pos + 1
    }
}

fn parse_operator2(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    if pos + 1 >= slen {
        return parse_operator1(state);
    }
    let cs = &state.input;
    if pos + 2 < slen && cs[pos] == b'<' && cs[pos + 1] == b'=' && cs[pos + 2] == b'>' {
        let val = cs[pos..pos + 3].to_vec();
        cur!(state).assign(TYPE_OPERATOR, pos, 3, &val);
        return pos + 3;
    }

    let ch = lookup_word(&cs[pos..pos + 2]);
    if ch != CHAR_NULL {
        let val = cs[pos..pos + 2].to_vec();
        cur!(state).assign(ch, pos, 2, &val);
        return pos + 2;
    }

    if cs[pos] == b':' {
        let val = vec![cs[pos]];
        cur!(state).assign(TYPE_COLON, pos, 1, &val);
        pos + 1
    } else {
        parse_operator1(state)
    }
}

fn parse_string(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let delim = state.input[pos];
    let cs = state.input.clone();
    parse_string_core(&cs, slen, pos, &mut cur!(state), delim, 1)
}

fn parse_estring(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let cs = &state.input;
    if pos + 2 >= slen || cs[pos + 1] != CHAR_SINGLE {
        return parse_word(state);
    }
    let cs = state.input.clone();
    parse_string_core(&cs, slen, pos, &mut cur!(state), CHAR_SINGLE, 2)
}

fn parse_ustring(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let cs = &state.input;
    if pos + 2 < slen && cs[pos + 1] == b'&' && cs[pos + 2] == b'\'' {
        state.pos += 2;
        let newpos = parse_string(state);
        cur!(state).str_open = b'u';
        if cur!(state).str_close == b'\'' {
            cur!(state).str_close = b'u';
        }
        newpos
    } else {
        parse_word(state)
    }
}

fn parse_qstring_core(state: &mut State, offset: usize) -> usize {
    let slen = state.input.len();
    let pos = state.pos + offset;
    let cs = &state.input;

    if pos >= slen
        || (cs[pos] != b'q' && cs[pos] != b'Q')
        || pos + 2 >= slen
        || cs[pos + 1] != b'\''
    {
        return parse_word(state);
    }

    let mut ch = cs[pos + 2];
    // C reads `ch` as a *signed* char, so any high byte (>=0x80) is negative and
    // satisfies `ch < 33`. Replicate that: bytes <33 or >127 fall back to a word.
    if ch < 33 || ch > 127 {
        return parse_word(state);
    }
    ch = match ch {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        b'<' => b'>',
        other => other,
    };

    let strend = memchr2(cs, pos + 3, slen, ch, b'\'');
    match strend {
        None => {
            let val = cs[pos + 3..slen].to_vec();
            cur!(state).assign(TYPE_STRING, pos + 3, slen - pos - 3, &val);
            cur!(state).str_open = b'q';
            cur!(state).str_close = CHAR_NULL;
            slen
        }
        Some(e) => {
            let val = cs[pos + 3..e].to_vec();
            cur!(state).assign(TYPE_STRING, pos + 3, e - pos - 3, &val);
            cur!(state).str_open = b'q';
            cur!(state).str_close = b'q';
            e + 2
        }
    }
}

fn parse_qstring(state: &mut State) -> usize {
    parse_qstring_core(state, 0)
}

fn parse_nqstring(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    if pos + 2 < slen && state.input[pos + 1] == CHAR_SINGLE {
        return parse_estring(state);
    }
    parse_qstring_core(state, 1)
}

fn parse_bstring(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let cs = &state.input;
    if pos + 2 >= slen || cs[pos + 1] != b'\'' {
        return parse_word(state);
    }
    let wlen = strlenspn(&cs[pos + 2..], b"01");
    if pos + 2 + wlen >= slen || cs[pos + 2 + wlen] != b'\'' {
        return parse_word(state);
    }
    let val = cs[pos..pos + wlen + 3].to_vec();
    cur!(state).assign(TYPE_NUMBER, pos, wlen + 3, &val);
    pos + 2 + wlen + 1
}

fn parse_xstring(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let cs = &state.input;
    if pos + 2 >= slen || cs[pos + 1] != b'\'' {
        return parse_word(state);
    }
    let wlen = strlenspn(&cs[pos + 2..], b"0123456789ABCDEFabcdef");
    if pos + 2 + wlen >= slen || cs[pos + 2 + wlen] != b'\'' {
        return parse_word(state);
    }
    let val = cs[pos..pos + wlen + 3].to_vec();
    cur!(state).assign(TYPE_NUMBER, pos, wlen + 3, &val);
    pos + 2 + wlen + 1
}

fn parse_bword(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let cs = &state.input;
    match memchr_from(cs, pos, b']') {
        None => {
            let val = cs[pos..slen].to_vec();
            cur!(state).assign(TYPE_BAREWORD, pos, slen - pos, &val);
            slen
        }
        Some(endptr) => {
            let val = cs[pos..endptr + 1].to_vec();
            cur!(state).assign(TYPE_BAREWORD, pos, endptr - pos + 1, &val);
            endptr + 1
        }
    }
}

fn parse_word(state: &mut State) -> usize {
    let pos = state.pos;
    let cs = &state.input;
    let stop = b" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r\"\xa0\x00";
    let wlen = strlencspn(&cs[pos..], stop);

    let val = cs[pos..pos + wlen].to_vec();
    cur!(state).assign(TYPE_BAREWORD, pos, wlen, &val);

    // inspect for "." / "`" inside the bareword
    let cur_len = cur!(state).len;
    for i in 0..cur_len {
        let delim = cur!(state).val[i];
        if delim == b'.' || delim == b'`' {
            let key: Vec<u8> = cur!(state).val[..i].to_vec();
            let ch = lookup_word(&key);
            if ch != TYPE_NONE && ch != TYPE_BAREWORD {
                cur!(state).clear();
                let v = cs[pos..pos + i].to_vec();
                cur!(state).assign(ch, pos, i, &v);
                return pos + i;
            }
        }
    }

    // normal lookup with whole word (only if it fits in the val buffer)
    if wlen < TOKEN_SIZE {
        let key: Vec<u8> = cur!(state).val[..wlen.min(TOKEN_SIZE - 1)].to_vec();
        let mut ch = lookup_word(&key);
        if ch == CHAR_NULL {
            ch = TYPE_BAREWORD;
        }
        cur!(state).type_ = ch;
    }
    pos + wlen
}

fn parse_tick(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let cs = state.input.clone();
    let newpos = parse_string_core(&cs, slen, pos, &mut cur!(state), CHAR_TICK, 1);

    let key: Vec<u8> = cur!(state).value().to_vec();
    let ch = lookup_word(&key);
    if ch == TYPE_FUNCTION {
        cur!(state).type_ = TYPE_FUNCTION;
    } else {
        cur!(state).type_ = TYPE_BAREWORD;
    }
    newpos
}

fn parse_var(state: &mut State) -> usize {
    let slen = state.input.len();
    let mut pos = state.pos + 1;
    let cs = &state.input;

    if pos < slen && cs[pos] == b'@' {
        pos += 1;
        cur!(state).count = 2;
    } else {
        cur!(state).count = 1;
    }

    if pos < slen {
        if cs[pos] == b'`' {
            state.pos = pos;
            let newpos = parse_tick(state);
            cur!(state).type_ = TYPE_VARIABLE;
            return newpos;
        } else if cs[pos] == CHAR_SINGLE || cs[pos] == CHAR_DOUBLE {
            state.pos = pos;
            let newpos = parse_string(state);
            cur!(state).type_ = TYPE_VARIABLE;
            return newpos;
        }
    }

    let stop = b" <>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r'`\"";
    let xlen = strlencspn(&cs[pos..], stop);
    if xlen == 0 {
        let empty: Vec<u8> = Vec::new();
        cur!(state).assign(TYPE_VARIABLE, pos, 0, &empty);
        pos
    } else {
        let val = cs[pos..pos + xlen].to_vec();
        cur!(state).assign(TYPE_VARIABLE, pos, xlen, &val);
        pos + xlen
    }
}

fn parse_money(state: &mut State) -> usize {
    let slen = state.input.len();
    let pos = state.pos;
    let cs = &state.input;

    if pos + 1 == slen {
        cur!(state).assign_char(TYPE_BAREWORD, pos, b'$');
        return slen;
    }

    let mut xlen = strlenspn(&cs[pos + 1..], b"0123456789.,");
    if xlen == 0 {
        if cs[pos + 1] == b'$' {
            // $$ ... find ending $$
            match memchr2(cs, pos + 2, slen, b'$', b'$') {
                None => {
                    let val = cs[pos + 2..slen].to_vec();
                    cur!(state).assign(TYPE_STRING, pos + 2, slen - (pos + 2), &val);
                    cur!(state).str_open = b'$';
                    cur!(state).str_close = CHAR_NULL;
                    slen
                }
                Some(strend) => {
                    let val = cs[pos + 2..strend].to_vec();
                    cur!(state).assign(TYPE_STRING, pos + 2, strend - (pos + 2), &val);
                    cur!(state).str_open = b'$';
                    cur!(state).str_close = b'$';
                    strend + 2
                }
            }
        } else {
            // pgsql $quoted$
            let letters = b"abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            xlen = strlenspn(&cs[pos + 1..], letters);
            if xlen == 0 {
                cur!(state).assign_char(TYPE_BAREWORD, pos, b'$');
                return pos + 1;
            }
            if pos + xlen + 1 == slen || cs[pos + xlen + 1] != b'$' {
                cur!(state).assign_char(TYPE_BAREWORD, pos, b'$');
                return pos + 1;
            }
            // $foobar$ ... find tag again: needle = cs[pos..pos+xlen+2]
            let needle = cs[pos..pos + xlen + 2].to_vec();
            let search_start = pos + xlen + 2;
            let found = find_subslice(cs, search_start, &needle);
            match found {
                None => {
                    let val = cs[search_start..slen].to_vec();
                    cur!(state).assign(TYPE_STRING, search_start, slen - search_start, &val);
                    cur!(state).str_open = b'$';
                    cur!(state).str_close = CHAR_NULL;
                    slen
                }
                Some(strend) => {
                    let val = cs[search_start..strend].to_vec();
                    cur!(state).assign(TYPE_STRING, search_start, strend - search_start, &val);
                    cur!(state).str_open = b'$';
                    cur!(state).str_close = b'$';
                    strend + xlen + 2
                }
            }
        }
    } else if xlen == 1 && cs[pos + 1] == b'.' {
        parse_word(state)
    } else {
        let val = cs[pos..pos + 1 + xlen].to_vec();
        cur!(state).assign(TYPE_NUMBER, pos, 1 + xlen, &val);
        pos + 1 + xlen
    }
}

/// `my_memmem` starting at `start`; returns absolute index.
fn find_subslice(cs: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start > cs.len() || cs.len() - start < needle.len() {
        return None;
    }
    cs[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| start + p)
}

fn parse_number(state: &mut State) -> usize {
    let slen = state.input.len();
    let mut pos = state.pos;
    let cs = &state.input;
    let mut have_e = false;
    let mut have_exp = false;

    if cs[pos] == b'0' && pos + 1 < slen {
        let digits: Option<&[u8]> = if cs[pos + 1] == b'X' || cs[pos + 1] == b'x' {
            Some(b"0123456789ABCDEFabcdef")
        } else if cs[pos + 1] == b'B' || cs[pos + 1] == b'b' {
            Some(b"01")
        } else {
            None
        };
        if let Some(d) = digits {
            let xlen = strlenspn(&cs[pos + 2..], d);
            if xlen == 0 {
                let val = cs[pos..pos + 2].to_vec();
                cur!(state).assign(TYPE_BAREWORD, pos, 2, &val);
                return pos + 2;
            } else {
                let val = cs[pos..pos + 2 + xlen].to_vec();
                cur!(state).assign(TYPE_NUMBER, pos, 2 + xlen, &val);
                return pos + 2 + xlen;
            }
        }
    }

    let start = pos;
    while pos < slen && cs[pos].is_ascii_digit() {
        pos += 1;
    }

    if pos < slen && cs[pos] == b'.' {
        pos += 1;
        while pos < slen && cs[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos - start == 1 {
            cur!(state).assign_char(TYPE_DOT, start, b'.');
            return pos;
        }
    }

    if pos < slen && (cs[pos] == b'E' || cs[pos] == b'e') {
        have_e = true;
        pos += 1;
        if pos < slen && (cs[pos] == b'+' || cs[pos] == b'-') {
            pos += 1;
        }
        while pos < slen && cs[pos].is_ascii_digit() {
            have_exp = true;
            pos += 1;
        }
    }

    if pos < slen && matches!(cs[pos], b'd' | b'D' | b'f' | b'F') {
        if pos + 1 == slen {
            pos += 1;
        } else if is_white(cs[pos + 1]) || cs[pos + 1] == b';' {
            pos += 1;
        } else if cs[pos + 1] == b'u' || cs[pos + 1] == b'U' {
            pos += 1;
        } else {
            // parse as number only
        }
    }

    if !(have_e && !have_exp) {
        let val = cs[start..pos].to_vec();
        cur!(state).assign(TYPE_NUMBER, start, pos - start, &val);
    }

    pos
}

/// Dispatch by first byte (port of `char_parse_map`).
fn parse_dispatch(state: &mut State) -> usize {
    let ch = state.input[state.pos];
    match ch {
        // 0..=32 whitespace/control
        0..=32 => parse_white(state),
        33 => parse_operator2(state),   // '!'
        34 => parse_string(state),      // '"'
        35 => parse_hash(state),        // '#'
        36 => parse_money(state),       // '$'
        37 => parse_operator1(state),   // '%'
        38 => parse_operator2(state),   // '&'
        39 => parse_string(state),      // '\''
        40 => parse_char(state),        // '('
        41 => parse_char(state),        // ')'
        42 => parse_operator2(state),   // '*'
        43 => parse_operator1(state),   // '+'
        44 => parse_char(state),        // ','
        45 => parse_dash(state),        // '-'
        46 => parse_number(state),      // '.'
        47 => parse_slash(state),       // '/'
        48..=57 => parse_number(state), // '0'..'9'
        58 => parse_operator2(state),   // ':'
        59 => parse_char(state),        // ';'
        60 => parse_operator2(state),   // '<'
        61 => parse_operator2(state),   // '='
        62 => parse_operator2(state),   // '>'
        63 => parse_other(state),       // '?'
        64 => parse_var(state),         // '@'
        65 => parse_word(state),        // 'A'
        66 => parse_bstring(state),     // 'B'
        67 | 68 => parse_word(state),   // 'C','D'
        69 => parse_estring(state),     // 'E'
        70..=77 => parse_word(state),   // 'F'..'M'
        78 => parse_nqstring(state),    // 'N'
        79 | 80 => parse_word(state),   // 'O','P'
        81 => parse_qstring(state),     // 'Q'
        82..=84 => parse_word(state),   // 'R','S','T'
        85 => parse_ustring(state),     // 'U'
        86 | 87 => parse_word(state),   // 'V','W'
        88 => parse_xstring(state),     // 'X'
        89 | 90 => parse_word(state),   // 'Y','Z'
        91 => parse_bword(state),       // '['
        92 => parse_backslash(state),   // '\\'
        93 => parse_other(state),       // ']'
        94 => parse_operator1(state),   // '^'
        95 => parse_word(state),        // '_'
        96 => parse_tick(state),        // '`'
        97 => parse_word(state),        // 'a'
        98 => parse_bstring(state),     // 'b'
        99 | 100 => parse_word(state),  // 'c','d'
        101 => parse_estring(state),    // 'e'
        102..=109 => parse_word(state), // 'f'..'m'
        110 => parse_nqstring(state),   // 'n'
        111 | 112 => parse_word(state), // 'o','p'
        113 => parse_qstring(state),    // 'q'
        114..=116 => parse_word(state), // 'r','s','t'
        117 => parse_ustring(state),    // 'u'
        118 | 119 => parse_word(state), // 'v','w'
        120 => parse_xstring(state),    // 'x'
        121 | 122 => parse_word(state), // 'y','z'
        123 => parse_char(state),       // '{'
        124 => parse_operator2(state),  // '|'
        125 => parse_char(state),       // '}'
        126 => parse_operator1(state),  // '~'
        127 => parse_white(state),      // DEL
        160 => parse_white(state),      // 0xa0 Latin-1 space
        _ => parse_word(state),         // 128..255 (except 160) -> parse_word
    }
}

/// `libinjection_sqli_tokenize`. Writes one token into `tokenvec[current]` and
/// returns `true` if a token was produced.
pub(crate) fn tokenize(state: &mut State) -> bool {
    let slen = state.input.len();
    if slen == 0 {
        return false;
    }

    cur!(state).clear();

    // beginning of string + quote-context => pretend input starts with a quote
    if state.pos == 0 && (state.flags & (FLAG_QUOTE_SINGLE | FLAG_QUOTE_DOUBLE) != 0) {
        let delim = flag2delim(state.flags);
        let cs = state.input.clone();
        state.pos = parse_string_core(&cs, slen, 0, &mut cur!(state), delim, 0);
        state.stats_tokens += 1;
        return true;
    }

    while state.pos < slen {
        state.pos = parse_dispatch(state);
        if cur!(state).type_ != CHAR_NULL {
            state.stats_tokens += 1;
            return true;
        }
    }
    false
}

// expose Token helpers needed by fold.rs
impl Token {
    pub(crate) fn arithmetic_op(&self) -> bool {
        self.is_arithmetic_op()
    }

    /// Public constructor for fold.rs's `last_comment` scratch token.
    pub(crate) fn new_pub() -> Self {
        Token::new()
    }

    /// Public wrapper for `st_assign`, used by `syntax_merge_words`.
    pub(crate) fn assign_pub(&mut self, stype: u8, pos: usize, len: usize, value: &[u8]) {
        self.assign(stype, pos, len, value);
    }
}
