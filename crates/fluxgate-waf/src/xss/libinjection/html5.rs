//! Faithful pure-Rust port of libinjection's HTML5 tokenizer
//! (`src/libinjection_html5.c`, BSD-3; see `data/ATTRIBUTION.md`).
//!
//! The C implementation drives a state machine through function pointers (the 44
//! `h5_state_*` functions). Here the current state is an [`H5State`] enum, and
//! [`H5::next`] dispatches to the matching state function. Each state function
//! returns `(bool, Option<H5State>)`: the `bool` is the C return value (1 = a
//! token was produced in `token_*`, 0 = done), and when it tail-calls another
//! state function in C we simply call the corresponding Rust method directly so
//! the dispatch reproduces the exact tokenization.
//!
//! Like the C, this operates on raw bytes (binary-safe) and never allocates.
//!
//! This is a literal 1:1 translation; the deliberate C-style lints (manual range
//! checks mirroring signed-`char` tests, identical `if`/`else` arms, etc.) are
//! allowed module-wide to keep the correspondence exact.
//!
//! `dead_code` is allowed because the [`H5State`] enum is a faithful 1:1 dispatch
//! table over the 44 C `h5_state_*` functions: several states are only ever
//! entered by a direct (tail) call from another state — never *stored* in
//! `self.state` — so their match arms are reachable at runtime but the variants
//! look "never constructed" to static analysis. Keeping the full table preserves
//! the structural correspondence with the C. `should_implement_trait` is allowed
//! because [`H5::next`] mirrors the C `libinjection_h5_next` name, not
//! `Iterator::next`.
#![allow(
    clippy::if_same_then_else,
    clippy::manual_range_contains,
    clippy::needless_return,
    clippy::nonminimal_bool,
    clippy::should_implement_trait,
    dead_code
)]

/// `enum html5_type` — the token kind reported in `token_type`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H5Type {
    DataText,
    TagNameOpen,
    TagNameClose,
    TagNameSelfclose,
    TagData,
    TagClose,
    AttrName,
    AttrValue,
    TagComment,
    Doctype,
}

/// `enum html5_flags` — the initial tokenizer state selected by [`H5::init`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum H5Flags {
    DataState,
    ValueNoQuote,
    ValueSingleQuote,
    ValueDoubleQuote,
    ValueBackQuote,
}

/// The current tokenizer state — one variant per `h5_state_*` entry function
/// that can be installed as `hs->state`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum H5State {
    Eof,
    Data,
    TagOpen,
    EndTagOpen,
    TagName,
    TagNameClose,
    BeforeAttributeName,
    AttributeName,
    AfterAttributeName,
    BeforeAttributeValue,
    AttributeValueDoubleQuote,
    AttributeValueSingleQuote,
    AttributeValueBackQuote,
    AttributeValueNoQuote,
    AfterAttributeValueQuotedState,
    SelfClosingStartTag,
    BogusComment,
    BogusComment2,
    MarkupDeclarationOpen,
    Comment,
    Cdata,
    Doctype,
}

const CHAR_NULL: u8 = 0;
const CHAR_BANG: u8 = 33;
const CHAR_DOUBLE: u8 = 34;
const CHAR_PERCENT: u8 = 37;
const CHAR_SINGLE: u8 = 39;
const CHAR_DASH: u8 = 45;
const CHAR_SLASH: u8 = 47;
const CHAR_GT: u8 = 62;
const CHAR_QUESTION: u8 = 63;
const CHAR_RIGHTB: u8 = 93;
const CHAR_TICK: u8 = 96;

/// `CHAR_EOF` is `-1` in C; here `h5_skip_white` returns `Option<u8>` and `None`
/// stands in for EOF.
type SkipResult = Option<u8>;

/// Port of `h5_state_t`. `s` is the input slice; `token_start`/`token_len`
/// describe the current token as a `(start, len)` window into `s`.
pub struct H5<'a> {
    s: &'a [u8],
    len: usize,
    pos: usize,
    is_close: bool,
    state: H5State,
    pub token_start: usize,
    pub token_len: usize,
    pub token_type: H5Type,
}

impl<'a> H5<'a> {
    /// `libinjection_h5_init`.
    pub fn init(s: &'a [u8], flags: H5Flags) -> Self {
        let state = match flags {
            H5Flags::DataState => H5State::Data,
            H5Flags::ValueNoQuote => H5State::BeforeAttributeName,
            H5Flags::ValueSingleQuote => H5State::AttributeValueSingleQuote,
            H5Flags::ValueDoubleQuote => H5State::AttributeValueDoubleQuote,
            H5Flags::ValueBackQuote => H5State::AttributeValueBackQuote,
        };
        H5 {
            s,
            len: s.len(),
            pos: 0,
            is_close: false,
            state,
            token_start: 0,
            token_len: 0,
            token_type: H5Type::DataText,
        }
    }

    /// `libinjection_h5_next` — returns `true` if a token was produced.
    ///
    /// (The C `LIBINJECTION_RESULT_ERROR` path requires `hs->state == NULL`,
    /// which cannot occur here: the state is always a valid enum, and the only
    /// `< pos` underflow guard in `h5_state_data` is preserved as a `debug_assert`
    /// — the tokenizer never moves `pos` past `len`.)
    pub fn next(&mut self) -> bool {
        self.dispatch(self.state)
    }

    fn dispatch(&mut self, state: H5State) -> bool {
        match state {
            H5State::Eof => self.state_eof(),
            H5State::Data => self.state_data(),
            H5State::TagOpen => self.state_tag_open(),
            H5State::EndTagOpen => self.state_end_tag_open(),
            H5State::TagName => self.state_tag_name(),
            H5State::TagNameClose => self.state_tag_name_close(),
            H5State::BeforeAttributeName => self.state_before_attribute_name(),
            H5State::AttributeName => self.state_attribute_name(),
            H5State::AfterAttributeName => self.state_after_attribute_name(),
            H5State::BeforeAttributeValue => self.state_before_attribute_value(),
            H5State::AttributeValueDoubleQuote => self.state_attribute_value_double_quote(),
            H5State::AttributeValueSingleQuote => self.state_attribute_value_single_quote(),
            H5State::AttributeValueBackQuote => self.state_attribute_value_back_quote(),
            H5State::AttributeValueNoQuote => self.state_attribute_value_no_quote(),
            H5State::AfterAttributeValueQuotedState => {
                self.state_after_attribute_value_quoted_state()
            }
            H5State::SelfClosingStartTag => self.state_self_closing_start_tag(),
            H5State::BogusComment => self.state_bogus_comment(),
            H5State::BogusComment2 => self.state_bogus_comment2(),
            H5State::MarkupDeclarationOpen => self.state_markup_declaration_open(),
            H5State::Comment => self.state_comment(),
            H5State::Cdata => self.state_cdata(),
            H5State::Doctype => self.state_doctype(),
        }
    }

    // -- helpers ------------------------------------------------------------

    /// `h5_is_white` — matches `strchr(" \t\n\v\f\r", ch) != NULL`.
    ///
    /// Note: `strchr(set, '\0')` returns a pointer to `set`'s terminating NUL —
    /// i.e. *non-NULL* — so the C predicate is **true for the NUL byte**. This is
    /// a load-bearing quirk: it makes a NUL inside a tag/attribute act as a
    /// whitespace separator. The differential test caught a token-split
    /// divergence here when this case was omitted.
    fn is_white(ch: u8) -> bool {
        matches!(ch, 0x00 | b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
    }

    /// `h5_skip_white` — advances `pos` over the IE/standard whitespace set and
    /// returns the next non-whitespace byte, or `None` at EOF.
    fn skip_white(&mut self) -> SkipResult {
        while self.pos < self.len {
            let ch = self.s[self.pos];
            match ch {
                0x00 | 0x20 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d => {
                    self.pos += 1;
                }
                _ => return Some(ch),
            }
        }
        None
    }

    // -- states -------------------------------------------------------------

    fn state_eof(&mut self) -> bool {
        false
    }

    /// `h5_state_data`.
    fn state_data(&mut self) -> bool {
        debug_assert!(self.len >= self.pos);
        match memchr(b'<', &self.s[self.pos..]) {
            None => {
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.token_type = H5Type::DataText;
                self.state = H5State::Eof;
                if self.token_len == 0 {
                    return false;
                }
                true
            }
            Some(rel) => {
                let idx = self.pos + rel;
                self.token_start = self.pos;
                self.token_type = H5Type::DataText;
                self.token_len = idx - self.pos;
                self.pos = idx + 1;
                self.state = H5State::TagOpen;
                if self.token_len == 0 {
                    return self.state_tag_open();
                }
                true
            }
        }
    }

    /// `h5_state_tag_open` — 12.2.4.8.
    fn state_tag_open(&mut self) -> bool {
        if self.pos >= self.len {
            return false;
        }
        let ch = self.s[self.pos];
        if ch == CHAR_BANG {
            self.pos += 1;
            self.state_markup_declaration_open()
        } else if ch == CHAR_SLASH {
            self.pos += 1;
            self.is_close = true;
            self.state_end_tag_open()
        } else if ch == CHAR_QUESTION {
            self.pos += 1;
            self.state_bogus_comment()
        } else if ch == CHAR_PERCENT {
            self.pos += 1;
            self.state_bogus_comment2()
        } else if ch.is_ascii_alphabetic() {
            self.state_tag_name()
        } else if ch == CHAR_NULL {
            // IE-ism: NULL characters are ignored
            self.state_tag_name()
        } else {
            if self.pos == 0 {
                return self.state_data();
            }
            self.token_start = self.pos - 1;
            self.token_len = 1;
            self.token_type = H5Type::DataText;
            self.state = H5State::Data;
            true
        }
    }

    /// `h5_state_end_tag_open` — 12.2.4.9.
    fn state_end_tag_open(&mut self) -> bool {
        if self.pos >= self.len {
            return false;
        }
        let ch = self.s[self.pos];
        if ch == CHAR_GT {
            return self.state_data();
        } else if ch.is_ascii_alphabetic() {
            return self.state_tag_name();
        }
        self.is_close = false;
        self.state_bogus_comment()
    }

    /// `h5_state_tag_name_close`.
    fn state_tag_name_close(&mut self) -> bool {
        self.is_close = false;
        self.token_start = self.pos;
        self.token_len = 1;
        self.token_type = H5Type::TagNameClose;
        self.pos += 1;
        if self.pos < self.len {
            self.state = H5State::Data;
        } else {
            self.state = H5State::Eof;
        }
        true
    }

    /// `h5_state_tag_name` — 12.2.4.10.
    fn state_tag_name(&mut self) -> bool {
        let mut pos = self.pos;
        while pos < self.len {
            let ch = self.s[pos];
            if ch == 0 {
                // allow and ignore nulls in tag name (non-standard, old browsers)
                pos += 1;
            } else if Self::is_white(ch) {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = H5Type::TagNameOpen;
                self.pos = pos + 1;
                self.state = H5State::BeforeAttributeName;
                return true;
            } else if ch == CHAR_SLASH {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = H5Type::TagNameOpen;
                self.pos = pos + 1;
                self.state = H5State::SelfClosingStartTag;
                return true;
            } else if ch == CHAR_GT {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                if self.is_close {
                    self.pos = pos + 1;
                    self.is_close = false;
                    self.token_type = H5Type::TagClose;
                    self.state = H5State::Data;
                } else {
                    self.pos = pos;
                    self.token_type = H5Type::TagNameOpen;
                    self.state = H5State::TagNameClose;
                }
                return true;
            } else {
                pos += 1;
            }
        }

        self.token_start = self.pos;
        self.token_len = self.len - self.pos;
        self.token_type = H5Type::TagNameOpen;
        self.state = H5State::Eof;
        true
    }

    /// `h5_state_before_attribute_name` — 12.2.4.34.
    fn state_before_attribute_name(&mut self) -> bool {
        // C uses a goto `tail_call:` loop for the CHAR_SLASH self-closing case.
        loop {
            match self.skip_white() {
                None => return false,
                Some(CHAR_SLASH) => {
                    self.pos += 1;
                    if self.pos < self.len && self.s[self.pos] != CHAR_GT {
                        continue; // goto tail_call
                    }
                    return self.state_self_closing_start_tag();
                }
                Some(CHAR_GT) => {
                    self.state = H5State::Data;
                    self.token_start = self.pos;
                    self.token_len = 1;
                    self.token_type = H5Type::TagNameClose;
                    self.pos += 1;
                    return true;
                }
                Some(_) => {
                    return self.state_attribute_name();
                }
            }
        }
    }

    /// `h5_state_attribute_name`.
    fn state_attribute_name(&mut self) -> bool {
        let mut pos = self.pos + 1;
        while pos < self.len {
            let ch = self.s[pos];
            if Self::is_white(ch) {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = H5Type::AttrName;
                self.state = H5State::AfterAttributeName;
                self.pos = pos + 1;
                return true;
            } else if ch == CHAR_SLASH {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = H5Type::AttrName;
                self.state = H5State::SelfClosingStartTag;
                self.pos = pos + 1;
                return true;
            } else if ch == b'=' {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = H5Type::AttrName;
                self.state = H5State::BeforeAttributeValue;
                self.pos = pos + 1;
                return true;
            } else if ch == CHAR_GT {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = H5Type::AttrName;
                self.state = H5State::TagNameClose;
                self.pos = pos;
                return true;
            } else {
                pos += 1;
            }
        }
        // EOF
        self.token_start = self.pos;
        self.token_len = self.len - self.pos;
        self.token_type = H5Type::AttrName;
        self.state = H5State::Eof;
        self.pos = self.len;
        true
    }

    /// `h5_state_after_attribute_name` — 12.2.4.36.
    fn state_after_attribute_name(&mut self) -> bool {
        match self.skip_white() {
            None => false,
            Some(CHAR_SLASH) => {
                self.pos += 1;
                self.state_self_closing_start_tag()
            }
            Some(b'=') => {
                self.pos += 1;
                self.state_before_attribute_value()
            }
            Some(CHAR_GT) => self.state_tag_name_close(),
            Some(_) => self.state_attribute_name(),
        }
    }

    /// `h5_state_before_attribute_value` — 12.2.4.37.
    fn state_before_attribute_value(&mut self) -> bool {
        let c = self.skip_white();
        match c {
            None => {
                self.state = H5State::Eof;
                false
            }
            Some(CHAR_DOUBLE) => self.state_attribute_value_double_quote(),
            Some(CHAR_SINGLE) => self.state_attribute_value_single_quote(),
            Some(CHAR_TICK) => self.state_attribute_value_back_quote(),
            Some(_) => self.state_attribute_value_no_quote(),
        }
    }

    /// `h5_state_attribute_value_quote` (shared body of the three quoted states).
    fn state_attribute_value_quote(&mut self, qchar: u8) -> bool {
        // skip initial quote in normal case; not when pos == 0 (we started in a
        // non-data state — `'><foo` wants a 0-length attribute value)
        if self.pos > 0 {
            self.pos += 1;
        }
        match memchr(qchar, &self.s[self.pos..]) {
            None => {
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.token_type = H5Type::AttrValue;
                self.state = H5State::Eof;
            }
            Some(rel) => {
                let idx = self.pos + rel;
                self.token_start = self.pos;
                self.token_len = idx - self.pos;
                self.token_type = H5Type::AttrValue;
                self.state = H5State::AfterAttributeValueQuotedState;
                self.pos += self.token_len + 1;
            }
        }
        true
    }

    fn state_attribute_value_double_quote(&mut self) -> bool {
        self.state_attribute_value_quote(CHAR_DOUBLE)
    }

    fn state_attribute_value_single_quote(&mut self) -> bool {
        self.state_attribute_value_quote(CHAR_SINGLE)
    }

    fn state_attribute_value_back_quote(&mut self) -> bool {
        self.state_attribute_value_quote(CHAR_TICK)
    }

    /// `h5_state_attribute_value_no_quote`.
    fn state_attribute_value_no_quote(&mut self) -> bool {
        let mut pos = self.pos;
        while pos < self.len {
            let ch = self.s[pos];
            if Self::is_white(ch) {
                self.token_type = H5Type::AttrValue;
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.pos = pos + 1;
                self.state = H5State::BeforeAttributeName;
                return true;
            } else if ch == CHAR_GT {
                self.token_type = H5Type::AttrValue;
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.pos = pos;
                self.state = H5State::TagNameClose;
                return true;
            }
            pos += 1;
        }
        // EOF
        self.state = H5State::Eof;
        self.token_start = self.pos;
        self.token_len = self.len - self.pos;
        self.token_type = H5Type::AttrValue;
        true
    }

    /// `h5_state_after_attribute_value_quoted_state` — 12.2.4.41.
    fn state_after_attribute_value_quoted_state(&mut self) -> bool {
        if self.pos >= self.len {
            return false;
        }
        let ch = self.s[self.pos];
        if Self::is_white(ch) {
            self.pos += 1;
            self.state_before_attribute_name()
        } else if ch == CHAR_SLASH {
            self.pos += 1;
            self.state_self_closing_start_tag()
        } else if ch == CHAR_GT {
            self.token_start = self.pos;
            self.token_len = 1;
            self.token_type = H5Type::TagNameClose;
            self.pos += 1;
            self.state = H5State::Data;
            true
        } else {
            self.state_before_attribute_name()
        }
    }

    /// `h5_state_self_closing_start_tag` — 12.2.4.43.
    fn state_self_closing_start_tag(&mut self) -> bool {
        if self.pos >= self.len {
            return false;
        }
        let ch = self.s[self.pos];
        if ch == CHAR_GT {
            self.token_start = self.pos - 1;
            self.token_len = 2;
            self.token_type = H5Type::TagNameSelfclose;
            self.state = H5State::Data;
            self.pos += 1;
            true
        } else {
            self.state_before_attribute_name()
        }
    }

    /// `h5_state_bogus_comment` — 12.2.4.44.
    fn state_bogus_comment(&mut self) -> bool {
        match memchr(CHAR_GT, &self.s[self.pos..]) {
            None => {
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.pos = self.len;
                self.state = H5State::Eof;
            }
            Some(rel) => {
                let idx = self.pos + rel;
                self.token_start = self.pos;
                self.token_len = idx - self.pos;
                self.pos = idx + 1;
                self.state = H5State::Data;
            }
        }
        self.token_type = H5Type::TagComment;
        true
    }

    /// `h5_state_bogus_comment2` — 12.2.4.44 ALT (IE `<% ... %>`).
    fn state_bogus_comment2(&mut self) -> bool {
        let mut pos = self.pos;
        loop {
            match memchr(CHAR_PERCENT, &self.s[pos..]) {
                None => {
                    self.token_start = self.pos;
                    self.token_len = self.len - self.pos;
                    self.pos = self.len;
                    self.token_type = H5Type::TagComment;
                    self.state = H5State::Eof;
                    return true;
                }
                Some(rel) => {
                    let idx = pos + rel;
                    // C: `idx + 1 >= hs->s + hs->len`
                    if idx + 1 >= self.len {
                        self.token_start = self.pos;
                        self.token_len = self.len - self.pos;
                        self.pos = self.len;
                        self.token_type = H5Type::TagComment;
                        self.state = H5State::Eof;
                        return true;
                    }
                    if self.s[idx + 1] != CHAR_GT {
                        pos = idx + 1;
                        continue;
                    }
                    // ends in %>
                    self.token_start = self.pos;
                    self.token_len = idx - self.pos;
                    self.pos = idx + 2;
                    self.state = H5State::Data;
                    self.token_type = H5Type::TagComment;
                    return true;
                }
            }
        }
    }

    /// `h5_state_markup_declaration_open` — 8.2.4.45.
    fn state_markup_declaration_open(&mut self) -> bool {
        let remaining = self.len - self.pos;
        let s = self.s;
        let p = self.pos;
        if remaining >= 7
            && (s[p] == b'D' || s[p] == b'd')
            && (s[p + 1] == b'O' || s[p + 1] == b'o')
            && (s[p + 2] == b'C' || s[p + 2] == b'c')
            && (s[p + 3] == b'T' || s[p + 3] == b't')
            && (s[p + 4] == b'Y' || s[p + 4] == b'y')
            && (s[p + 5] == b'P' || s[p + 5] == b'p')
            && (s[p + 6] == b'E' || s[p + 6] == b'e')
        {
            self.state_doctype()
        } else if remaining >= 7
            && s[p] == b'['
            && s[p + 1] == b'C'
            && s[p + 2] == b'D'
            && s[p + 3] == b'A'
            && s[p + 4] == b'T'
            && s[p + 5] == b'A'
            && s[p + 6] == b'['
        {
            self.pos += 7;
            self.state_cdata()
        } else if remaining >= 2 && s[p] == b'-' && s[p + 1] == b'-' {
            self.pos += 2;
            self.state_comment()
        } else {
            self.state_bogus_comment()
        }
    }

    /// `h5_state_comment` — 12.2.4.48..51. Comments end by EOF, `-->`, or `-!>`.
    fn state_comment(&mut self) -> bool {
        let end = self.len;
        let mut pos = self.pos;
        loop {
            let idx = match memchr(CHAR_DASH, &self.s[pos..]) {
                None => {
                    self.state = H5State::Eof;
                    self.token_start = self.pos;
                    self.token_len = self.len - self.pos;
                    self.token_type = H5Type::TagComment;
                    return true;
                }
                Some(rel) => pos + rel,
            };

            // C: `idx > hs->s + hs->len - 3`  (less than 3 chars left)
            if idx > self.len.wrapping_sub(3) || self.len < 3 {
                self.state = H5State::Eof;
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.token_type = H5Type::TagComment;
                return true;
            }

            let mut offset = 1usize;

            // skip all nulls
            while idx + offset < end && self.s[idx + offset] == 0 {
                offset += 1;
            }
            if idx + offset == end {
                self.state = H5State::Eof;
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.token_type = H5Type::TagComment;
                return true;
            }

            let ch = self.s[idx + offset];
            if ch != CHAR_DASH && ch != CHAR_BANG {
                pos = idx + 1;
                continue;
            }

            offset += 1;
            if idx + offset == end {
                self.state = H5State::Eof;
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.token_type = H5Type::TagComment;
                return true;
            }

            let ch = self.s[idx + offset];
            if ch != CHAR_GT {
                pos = idx + 1;
                continue;
            }
            offset += 1;

            // ends in --> or -!>
            self.token_start = self.pos;
            self.token_len = idx - self.pos;
            self.pos = idx + offset;
            self.state = H5State::Data;
            self.token_type = H5Type::TagComment;
            return true;
        }
    }

    /// `h5_state_cdata`.
    fn state_cdata(&mut self) -> bool {
        let mut pos = self.pos;
        loop {
            let idx = match memchr(CHAR_RIGHTB, &self.s[pos..]) {
                None => {
                    self.state = H5State::Eof;
                    self.token_start = self.pos;
                    self.token_len = self.len - self.pos;
                    self.token_type = H5Type::DataText;
                    return true;
                }
                Some(rel) => pos + rel,
            };

            // less than 3 chars left
            if idx > self.len.wrapping_sub(3) || self.len < 3 {
                self.state = H5State::Eof;
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.token_type = H5Type::DataText;
                return true;
            } else if self.s[idx + 1] == CHAR_RIGHTB && self.s[idx + 2] == CHAR_GT {
                self.state = H5State::Data;
                self.token_start = self.pos;
                self.token_len = idx - self.pos;
                self.pos = idx + 3;
                self.token_type = H5Type::DataText;
                return true;
            } else {
                pos = idx + 1;
            }
        }
    }

    /// `h5_state_doctype` — 8.2.4.52.
    fn state_doctype(&mut self) -> bool {
        self.token_start = self.pos;
        self.token_type = H5Type::Doctype;
        match memchr(CHAR_GT, &self.s[self.pos..]) {
            None => {
                self.state = H5State::Eof;
                self.token_len = self.len - self.pos;
            }
            Some(rel) => {
                let idx = self.pos + rel;
                self.state = H5State::Data;
                self.token_len = idx - self.pos;
                self.pos = idx + 1;
            }
        }
        true
    }
}

/// `memchr` over a byte slice — the C uses `memchr` from `<string.h>`.
#[inline]
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    memchr::memchr(needle, haystack)
}
