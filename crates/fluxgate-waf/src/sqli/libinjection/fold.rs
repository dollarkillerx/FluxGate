//! Token folding — port of `libinjection_sqli_fold` and `syntax_merge_words`.
//!
//! This is a deliberately literal 1:1 translation of the C `else if` cascade.
//! Several Clippy style lints fire precisely *because* the structure mirrors the
//! C source: distinct semantic fold rules that happen to share an identical body
//! (`if_same_then_else`), the `if left > 0 { left -= 1 }` decrements
//! (`implicit_saturating_sub` — but `left.saturating_sub(1)` would *also* be
//! wrong: when `left == 0` the C code leaves `left` untouched, which the guarded
//! form preserves), the explicit `!(have_e && !have_exp)`-style conditions, and
//! the nested case/sub-case `if`s. Rewriting them would obscure the
//! correspondence to libinjection and raise the risk of a divergence in a
//! security control, so they are allowed module-wide rather than "cleaned up".
#![allow(
    clippy::if_same_then_else,
    clippy::implicit_saturating_sub,
    clippy::collapsible_if,
    clippy::manual_ignore_case_cmp
)]

use super::tokenizer::{tokenize, State, Token, MAX_TOKENS};
use super::*;

/// `cstrcasecmp(LITERAL, tok.val, tok.len) == 0`, where `LITERAL` is upper-case.
fn tok_ci_eq(tok: &Token, upper: &[u8]) -> bool {
    let v = tok.value();
    if v.len() != upper.len() {
        return false;
    }
    v.iter()
        .zip(upper)
        .all(|(&a, &b)| a.to_ascii_uppercase() == b)
}

/// `streq(tok.val, s)` — exact (case-sensitive) value compare.
fn tok_eq(tok: &Token, s: &[u8]) -> bool {
    tok.value() == s
}

/// `syntax_merge_words(a, b)`: if `a` and `b` are mergeable phrase tokens and
/// `"A B"` is a known keyword, rewrite `a` and return `true`.
fn syntax_merge_words(a: &mut Token, b: &Token) -> bool {
    let a_ok = matches!(
        a.type_,
        TYPE_KEYWORD
            | TYPE_BAREWORD
            | TYPE_OPERATOR
            | TYPE_UNION
            | TYPE_FUNCTION
            | TYPE_EXPRESSION
            | TYPE_TSQL
            | TYPE_SQLTYPE
    );
    if !a_ok {
        return false;
    }
    let b_ok = matches!(
        b.type_,
        TYPE_KEYWORD
            | TYPE_BAREWORD
            | TYPE_OPERATOR
            | TYPE_UNION
            | TYPE_FUNCTION
            | TYPE_EXPRESSION
            | TYPE_TSQL
            | TYPE_SQLTYPE
            | TYPE_LOGIC_OPERATOR
    );
    if !b_ok {
        return false;
    }

    let sz1 = a.len;
    let sz2 = b.len;
    let sz3 = sz1 + sz2 + 1;
    if sz3 >= super::TOKEN_SIZE {
        return false;
    }

    let mut tmp = Vec::with_capacity(sz3);
    tmp.extend_from_slice(&a.val[..sz1]);
    tmp.push(b' ');
    tmp.extend_from_slice(&b.val[..sz2]);

    let ch = lookup_word(&tmp);
    if ch != CHAR_NULL {
        // st_assign(a, ch, a.pos, sz3, tmp)
        let pos = a.pos;
        a.assign_pub(ch, pos, sz3, &tmp);
        true
    } else {
        false
    }
}

/// `syntax_merge_words(&tokenvec[left], &tokenvec[left+1])`, writing the merged
/// token back into `tokenvec[left]` on success.
fn try_merge_words(state: &mut State, left: usize) -> bool {
    let b = state.tokenvec[left + 1].clone();
    let mut a = state.tokenvec[left].clone();
    if syntax_merge_words(&mut a, &b) {
        state.tokenvec[left] = a;
        true
    } else {
        false
    }
}

/// `libinjection_sqli_fold`. Returns the number of folded tokens (`left`,
/// capped at [`MAX_TOKENS`]). Fingerprint reads `tokenvec[0..ret]`.
pub(crate) fn fold(state: &mut State) -> usize {
    let mut last_comment = Token::new_pub();

    let mut pos: usize = 0;
    let mut left: usize = 0;
    let mut more = true;

    // Skip leading comments, '(', sqltype, unary ops.
    state.current = 0;
    while more {
        state.current = 0;
        more = tokenize(state);
        let cur = &state.tokenvec[0];
        if !(cur.type_ == TYPE_COMMENT
            || cur.type_ == TYPE_LEFTPARENS
            || cur.type_ == TYPE_SQLTYPE
            || cur.is_unary_op())
        {
            break;
        }
    }

    if !more {
        return 0;
    } else {
        pos += 1;
    }

    loop {
        // 5-token special cases
        if pos >= MAX_TOKENS {
            let t = &state.tokenvec;
            let case1 = t[0].type_ == TYPE_NUMBER
                && (t[1].type_ == TYPE_OPERATOR || t[1].type_ == TYPE_COMMA)
                && t[2].type_ == TYPE_LEFTPARENS
                && t[3].type_ == TYPE_NUMBER
                && t[4].type_ == TYPE_RIGHTPARENS;
            let case2 = t[0].type_ == TYPE_BAREWORD
                && t[1].type_ == TYPE_OPERATOR
                && t[2].type_ == TYPE_LEFTPARENS
                && (t[3].type_ == TYPE_BAREWORD || t[3].type_ == TYPE_NUMBER)
                && t[4].type_ == TYPE_RIGHTPARENS;
            let case3 = t[0].type_ == TYPE_NUMBER
                && t[1].type_ == TYPE_RIGHTPARENS
                && t[2].type_ == TYPE_COMMA
                && t[3].type_ == TYPE_LEFTPARENS
                && t[4].type_ == TYPE_NUMBER;
            let case4 = t[0].type_ == TYPE_BAREWORD
                && t[1].type_ == TYPE_RIGHTPARENS
                && t[2].type_ == TYPE_OPERATOR
                && t[3].type_ == TYPE_LEFTPARENS
                && t[4].type_ == TYPE_BAREWORD;
            if case1 || case2 || case3 || case4 {
                if pos > MAX_TOKENS {
                    state.tokenvec[1] = state.tokenvec[MAX_TOKENS].clone();
                    pos = 2;
                    left = 0;
                } else {
                    pos = 1;
                    left = 0;
                }
            }
        }

        if !more || left >= MAX_TOKENS {
            left = pos;
            break;
        }

        // get up to two tokens
        while more && pos <= MAX_TOKENS && (pos - left) < 2 {
            state.current = pos;
            more = tokenize(state);
            if more {
                if state.tokenvec[pos].type_ == TYPE_COMMENT {
                    last_comment = state.tokenvec[pos].clone();
                } else {
                    last_comment.type_ = CHAR_NULL;
                    pos += 1;
                }
            }
        }

        if pos - left < 2 {
            left = pos;
            continue;
        }

        let lt = state.tokenvec[left].type_;
        let l1t = state.tokenvec[left + 1].type_;

        // "ss" -> "s"
        if lt == TYPE_STRING && l1t == TYPE_STRING {
            pos -= 1;
            state.stats_folds += 1;
            continue;
        } else if lt == TYPE_SEMICOLON && l1t == TYPE_SEMICOLON {
            pos -= 1;
            state.stats_folds += 1;
            continue;
        } else if (lt == TYPE_OPERATOR || lt == TYPE_LOGIC_OPERATOR)
            && (state.tokenvec[left + 1].is_unary_op() || l1t == TYPE_SQLTYPE)
        {
            pos -= 1;
            state.stats_folds += 1;
            left = 0;
            continue;
        } else if lt == TYPE_LEFTPARENS && state.tokenvec[left + 1].is_unary_op() {
            pos -= 1;
            state.stats_folds += 1;
            if left > 0 {
                left -= 1;
            }
            continue;
        } else if try_merge_words(state, left) {
            pos -= 1;
            state.stats_folds += 1;
            if left > 0 {
                left -= 1;
            }
            continue;
        } else if lt == TYPE_SEMICOLON
            && l1t == TYPE_FUNCTION
            && (state.tokenvec[left + 1].val[0] == b'I' || state.tokenvec[left + 1].val[0] == b'i')
            && (state.tokenvec[left + 1].val[1] == b'F' || state.tokenvec[left + 1].val[1] == b'f')
        {
            state.tokenvec[left + 1].type_ = TYPE_TSQL;
            continue;
        } else if (lt == TYPE_BAREWORD || lt == TYPE_VARIABLE) && l1t == TYPE_LEFTPARENS && {
            let v = &state.tokenvec[left];
            tok_ci_eq(v, b"USER_ID")
                || tok_ci_eq(v, b"USER_NAME")
                || tok_ci_eq(v, b"DATABASE")
                || tok_ci_eq(v, b"PASSWORD")
                || tok_ci_eq(v, b"USER")
                || tok_ci_eq(v, b"CURRENT_USER")
                || tok_ci_eq(v, b"CURRENT_DATE")
                || tok_ci_eq(v, b"CURRENT_TIME")
                || tok_ci_eq(v, b"CURRENT_TIMESTAMP")
                || tok_ci_eq(v, b"LOCALTIME")
                || tok_ci_eq(v, b"LOCALTIMESTAMP")
        } {
            state.tokenvec[left].type_ = TYPE_FUNCTION;
            continue;
        } else if lt == TYPE_KEYWORD
            && (tok_ci_eq(&state.tokenvec[left], b"IN")
                || tok_ci_eq(&state.tokenvec[left], b"NOT IN"))
        {
            if l1t == TYPE_LEFTPARENS {
                state.tokenvec[left].type_ = TYPE_OPERATOR;
            } else {
                state.tokenvec[left].type_ = TYPE_BAREWORD;
            }
            continue;
        } else if lt == TYPE_OPERATOR
            && (tok_ci_eq(&state.tokenvec[left], b"LIKE")
                || tok_ci_eq(&state.tokenvec[left], b"NOT LIKE"))
        {
            if l1t == TYPE_LEFTPARENS {
                state.tokenvec[left].type_ = TYPE_FUNCTION;
            }
        } else if lt == TYPE_SQLTYPE
            && (l1t == TYPE_BAREWORD
                || l1t == TYPE_NUMBER
                || l1t == TYPE_SQLTYPE
                || l1t == TYPE_LEFTPARENS
                || l1t == TYPE_FUNCTION
                || l1t == TYPE_VARIABLE
                || l1t == TYPE_STRING)
        {
            state.tokenvec[left] = state.tokenvec[left + 1].clone();
            pos -= 1;
            state.stats_folds += 1;
            left = 0;
            continue;
        } else if lt == TYPE_COLLATE && l1t == TYPE_BAREWORD {
            if state.tokenvec[left + 1].value().contains(&b'_') {
                state.tokenvec[left + 1].type_ = TYPE_SQLTYPE;
                left = 0;
            }
        } else if lt == TYPE_BACKSLASH {
            if state.tokenvec[left + 1].arithmetic_op() {
                state.tokenvec[left].type_ = TYPE_NUMBER;
            } else {
                state.tokenvec[left] = state.tokenvec[left + 1].clone();
                pos -= 1;
                state.stats_folds += 1;
            }
            left = 0;
            continue;
        } else if lt == TYPE_LEFTPARENS && l1t == TYPE_LEFTPARENS {
            pos -= 1;
            left = 0;
            state.stats_folds += 1;
            continue;
        } else if lt == TYPE_RIGHTPARENS && l1t == TYPE_RIGHTPARENS {
            pos -= 1;
            left = 0;
            state.stats_folds += 1;
            continue;
        } else if lt == TYPE_LEFTBRACE && l1t == TYPE_BAREWORD {
            if state.tokenvec[left + 1].len == 0 {
                state.tokenvec[left + 1].type_ = TYPE_EVIL;
                return left + 2;
            }
            left = 0;
            pos -= 2;
            state.stats_folds += 2;
            continue;
        } else if l1t == TYPE_RIGHTBRACE {
            pos -= 1;
            left = 0;
            state.stats_folds += 1;
            continue;
        }

        // grab a third token
        while more && pos <= MAX_TOKENS && pos - left < 3 {
            state.current = pos;
            more = tokenize(state);
            if more {
                if state.tokenvec[pos].type_ == TYPE_COMMENT {
                    last_comment = state.tokenvec[pos].clone();
                } else {
                    last_comment.type_ = CHAR_NULL;
                    pos += 1;
                }
            }
        }

        if pos - left < 3 {
            left = pos;
            continue;
        }

        let lt = state.tokenvec[left].type_;
        let l1t = state.tokenvec[left + 1].type_;
        let l2t = state.tokenvec[left + 2].type_;

        // three-token folding
        if lt == TYPE_NUMBER && l1t == TYPE_OPERATOR && l2t == TYPE_NUMBER {
            pos -= 2;
            left = 0;
            continue;
        } else if lt == TYPE_OPERATOR && l1t != TYPE_LEFTPARENS && l2t == TYPE_OPERATOR {
            left = 0;
            pos -= 2;
            continue;
        } else if lt == TYPE_LOGIC_OPERATOR && l2t == TYPE_LOGIC_OPERATOR {
            pos -= 2;
            left = 0;
            continue;
        } else if lt == TYPE_VARIABLE
            && l1t == TYPE_OPERATOR
            && (l2t == TYPE_VARIABLE || l2t == TYPE_NUMBER || l2t == TYPE_BAREWORD)
        {
            pos -= 2;
            left = 0;
            continue;
        } else if (lt == TYPE_BAREWORD || lt == TYPE_NUMBER)
            && l1t == TYPE_OPERATOR
            && (l2t == TYPE_NUMBER || l2t == TYPE_BAREWORD)
        {
            pos -= 2;
            left = 0;
            continue;
        } else if (lt == TYPE_BAREWORD
            || lt == TYPE_NUMBER
            || lt == TYPE_VARIABLE
            || lt == TYPE_STRING)
            && l1t == TYPE_OPERATOR
            && tok_eq(&state.tokenvec[left + 1], b"::")
            && l2t == TYPE_SQLTYPE
        {
            pos -= 2;
            left = 0;
            state.stats_folds += 2;
            continue;
        } else if (lt == TYPE_BAREWORD
            || lt == TYPE_NUMBER
            || lt == TYPE_STRING
            || lt == TYPE_VARIABLE)
            && l1t == TYPE_COMMA
            && (l2t == TYPE_NUMBER
                || l2t == TYPE_BAREWORD
                || l2t == TYPE_STRING
                || l2t == TYPE_VARIABLE)
        {
            pos -= 2;
            left = 0;
            continue;
        } else if (lt == TYPE_EXPRESSION || lt == TYPE_GROUP || lt == TYPE_COMMA)
            && state.tokenvec[left + 1].is_unary_op()
            && l2t == TYPE_LEFTPARENS
        {
            state.tokenvec[left + 1] = state.tokenvec[left + 2].clone();
            pos -= 1;
            left = 0;
            continue;
        } else if (lt == TYPE_KEYWORD || lt == TYPE_EXPRESSION || lt == TYPE_GROUP)
            && state.tokenvec[left + 1].is_unary_op()
            && (l2t == TYPE_NUMBER
                || l2t == TYPE_BAREWORD
                || l2t == TYPE_VARIABLE
                || l2t == TYPE_STRING
                || l2t == TYPE_FUNCTION)
        {
            state.tokenvec[left + 1] = state.tokenvec[left + 2].clone();
            pos -= 1;
            left = 0;
            continue;
        } else if lt == TYPE_COMMA
            && state.tokenvec[left + 1].is_unary_op()
            && (l2t == TYPE_NUMBER
                || l2t == TYPE_BAREWORD
                || l2t == TYPE_VARIABLE
                || l2t == TYPE_STRING)
        {
            state.tokenvec[left + 1] = state.tokenvec[left + 2].clone();
            left = 0;
            pos -= 3;
            continue;
        } else if lt == TYPE_COMMA && state.tokenvec[left + 1].is_unary_op() && l2t == TYPE_FUNCTION
        {
            state.tokenvec[left + 1] = state.tokenvec[left + 2].clone();
            pos -= 1;
            left = 0;
            continue;
        } else if lt == TYPE_BAREWORD && l1t == TYPE_DOT && l2t == TYPE_BAREWORD {
            pos -= 2;
            left = 0;
            continue;
        } else if lt == TYPE_EXPRESSION && l1t == TYPE_DOT && l2t == TYPE_BAREWORD {
            state.tokenvec[left + 1] = state.tokenvec[left + 2].clone();
            pos -= 1;
            left = 0;
            continue;
        } else if lt == TYPE_FUNCTION && l1t == TYPE_LEFTPARENS && l2t != TYPE_RIGHTPARENS {
            if tok_ci_eq(&state.tokenvec[left], b"USER") {
                state.tokenvec[left].type_ = TYPE_BAREWORD;
            }
        }

        // no folding -- advance
        left += 1;
    }

    // re-attach trailing comment
    if left < MAX_TOKENS && last_comment.type_ == TYPE_COMMENT {
        state.tokenvec[left] = last_comment;
        left += 1;
    }

    if left > MAX_TOKENS {
        left = MAX_TOKENS;
    }

    left
}
