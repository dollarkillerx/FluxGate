//! A small SQL tokenizer. It classifies bytes into the token classes the
//! detector reasons over — strings, numbers, operators, keywords, comments,
//! punctuation — so detection works on *structure* instead of raw substrings.
//! Input is expected pre-lowercased.

/// A token: a one-byte class plus (for words/operators) its lowercased text,
/// **borrowed** from the tokenized input — no per-token heap allocation.
pub struct Token<'a> {
    pub class: u8,
    pub text: &'a str,
}

impl<'a> Token<'a> {
    fn bare(class: u8) -> Self {
        Token { class, text: "" }
    }
    fn word(class: u8, text: &'a str) -> Self {
        Token { class, text }
    }
}

const LOGIC: &[&str] = &[
    "and", "or", "xor", "not", "like", "rlike", "regexp", "in", "is", "between", "div", "mod",
    "sounds",
];

const KEYWORDS: &[&str] = &[
    "select",
    "from",
    "where",
    "group",
    "order",
    "by",
    "having",
    "limit",
    "into",
    "values",
    "table",
    "database",
    "schema",
    "set",
    "declare",
    "exec",
    "execute",
    "drop",
    "create",
    "alter",
    "truncate",
    "insert",
    "update",
    "delete",
    "replace",
    "grant",
    "join",
    "distinct",
    "all",
    "top",
    "case",
    "when",
    "then",
    "else",
    "end",
    "null",
    "default",
    "outfile",
    "dumpfile",
    "procedure",
    "waitfor",
    "delay",
    "as",
    "on",
    "call",
    "use",
    "describe",
];

const FUNCS: &[&str] = &[
    "sleep",
    "benchmark",
    "pg_sleep",
    "load_file",
    "updatexml",
    "extractvalue",
    "concat",
    "concat_ws",
    "char",
    "ascii",
    "ord",
    "hex",
    "unhex",
    "substring",
    "substr",
    "mid",
    "count",
    "group_concat",
    "version",
    "user",
    "exp",
    "floor",
    "rand",
    "cast",
    "convert",
    "md5",
    "current_user",
    "system_user",
    "session_user",
    "if",
    "ifnull",
    "nullif",
    "coalesce",
    "make_set",
    "elt",
    "field",
    "json_keys",
];

pub fn tokenize(s: &str) -> Vec<Token<'_>> {
    let b = s.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // -- comment (requires trailing whitespace / EOL, as SQL does)
        if c == b'-'
            && i + 1 < b.len()
            && b[i + 1] == b'-'
            && (i + 2 >= b.len() || b[i + 2].is_ascii_whitespace())
        {
            let mut j = i + 2;
            while j < b.len() && b[j] != b'\n' {
                j += 1;
            }
            toks.push(Token::bare(b'c'));
            i = j;
            continue;
        }
        // # comment
        if c == b'#' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'\n' {
                j += 1;
            }
            toks.push(Token::bare(b'c'));
            i = j;
            continue;
        }
        // /* ... */ comment
        if c == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            let mut j = i + 2;
            while j + 1 < b.len() && !(b[j] == b'*' && b[j + 1] == b'/') {
                j += 1;
            }
            j = if j + 1 < b.len() { j + 2 } else { b.len() };
            toks.push(Token::bare(b'c'));
            i = j;
            continue;
        }
        // string literal ' … ' or " … " (handles \-escape and doubled-quote)
        if c == b'\'' || c == b'"' {
            let quote = c;
            let mut j = i + 1;
            while j < b.len() {
                if b[j] == b'\\' && j + 1 < b.len() {
                    j += 2;
                    continue;
                }
                if b[j] == quote {
                    if j + 1 < b.len() && b[j + 1] == quote {
                        j += 2;
                        continue;
                    }
                    j += 1;
                    break;
                }
                j += 1;
            }
            toks.push(Token::bare(b's'));
            i = j;
            continue;
        }
        // number (decimal / hex / scientific)
        if c.is_ascii_digit() || (c == b'.' && i + 1 < b.len() && b[i + 1].is_ascii_digit()) {
            let mut j;
            if c == b'0' && i + 1 < b.len() && (b[i + 1] | 0x20) == b'x' {
                j = i + 2;
                while j < b.len() && b[j].is_ascii_hexdigit() {
                    j += 1;
                }
            } else {
                j = i;
                while j < b.len()
                    && (b[j].is_ascii_digit() || b[j] == b'.' || (b[j] | 0x20) == b'e')
                {
                    j += 1;
                }
            }
            toks.push(Token::bare(b'1'));
            i = j;
            continue;
        }
        // variable @x / @@x
        if c == b'@' {
            let mut j = i + 1;
            if j < b.len() && b[j] == b'@' {
                j += 1;
            }
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            toks.push(Token::bare(b'v'));
            i = j;
            continue;
        }
        // word / identifier / keyword
        if c.is_ascii_alphabetic() || c == b'_' {
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            let word = &s[i..j];
            let mut k = j;
            while k < b.len() && b[k].is_ascii_whitespace() {
                k += 1;
            }
            let next_paren = k < b.len() && b[k] == b'(';
            toks.push(Token::word(classify_word(word, next_paren), word));
            i = j;
            continue;
        }
        // punctuation
        match c {
            b'(' => toks.push(Token::bare(b'(')),
            b')' => toks.push(Token::bare(b')')),
            b',' => toks.push(Token::bare(b',')),
            b';' => toks.push(Token::bare(b';')),
            _ if is_op_char(c) => {
                let mut j = i;
                while j < b.len() && is_op_char(b[j]) {
                    j += 1;
                }
                toks.push(Token::word(b'o', &s[i..j]));
                i = j;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    toks
}

fn classify_word(w: &str, next_paren: bool) -> u8 {
    if w == "union" {
        return b'U';
    }
    if LOGIC.contains(&w) {
        return b'o';
    }
    if next_paren && FUNCS.contains(&w) {
        return b'f';
    }
    if KEYWORDS.contains(&w) {
        return b'k';
    }
    b'n'
}

fn is_op_char(c: u8) -> bool {
    matches!(
        c,
        b'=' | b'<'
            | b'>'
            | b'!'
            | b'+'
            | b'-'
            | b'*'
            | b'/'
            | b'%'
            | b'^'
            | b'|'
            | b'&'
            | b'~'
            | b':'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(s: &str) -> String {
        tokenize(s).iter().map(|t| t.class as char).collect()
    }

    #[test]
    fn basic_classes() {
        assert_eq!(classes("1=1"), "1o1");
        assert_eq!(classes("union select 1"), "Uk1");
        assert_eq!(classes("'abc'"), "s");
        assert_eq!(classes("sleep(5)"), "f(1)");
        assert_eq!(classes("a -- comment"), "nc");
        assert_eq!(classes("1;drop"), "1;k");
    }

    #[test]
    fn logic_words_are_operators() {
        let t = tokenize("1 or 1");
        assert_eq!(t[1].class, b'o');
        assert_eq!(t[1].text, "or");
    }
}
