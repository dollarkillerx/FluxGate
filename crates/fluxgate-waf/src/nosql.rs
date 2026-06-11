//! NoSQL (MongoDB) injection. Flags Mongo query operators used **as operators**
//! — `$where`/`$ne`/`$gt`… in operator position — not the `$5` price or `$name`
//! variable that show up in ordinary text. Input is the shared lowercased view.

use fluxgate_core::WafRisk;

/// Operators that run server-side JavaScript — always high-signal.
const JS_OPS: &[&str] = &["$where", "$function", "$accumulator", "$expr"];

/// Comparison / logical operators — medium when in operator position.
const OPS: &[&str] = &[
    "$ne",
    "$gte",
    "$gt",
    "$lte",
    "$lt",
    "$regex",
    "$nin",
    "$in",
    "$or",
    "$and",
    "$nor",
    "$not",
    "$exists",
    "$elemmatch",
    "$mod",
    "$all",
    "$size",
];

pub fn detect(lower: &str) -> Option<(WafRisk, String)> {
    for op in JS_OPS {
        if lower.contains(op) {
            return Some((WafRisk::High, format!("op:{op}")));
        }
    }
    let b = lower.as_bytes();
    for op in OPS {
        // Check *every* occurrence, not just the first: a benign prefix that
        // merely contains the operator's bytes (`$network`, `$invalid`) must not
        // shadow a real operator (`{"$ne":null}`) later in the value.
        for (pos, _) in lower.match_indices(op) {
            let after = pos + op.len();
            // `$ne` must not be the prefix of a longer word like `$net`: the byte
            // right after the operator name must not be a letter…
            let not_word = b.get(after).is_none_or(|c| !c.is_ascii_alphabetic());
            // …and the operator must sit in operator position (next non-space byte
            // is a JSON/array delimiter or an assignment), so prose like
            // `cost $gt 5` or `$5` never trips.
            if not_word && operator_position(b, after) {
                return Some((WafRisk::Medium, format!("op:{op}")));
            }
        }
    }
    None
}

fn operator_position(b: &[u8], after: usize) -> bool {
    let mut i = after;
    while i < b.len() && b[i] == b' ' {
        i += 1;
    }
    matches!(
        b.get(i),
        Some(b']') | Some(b':') | Some(b'}') | Some(b'=') | Some(b'"') | Some(b'\'')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risk(v: &str) -> Option<WafRisk> {
        detect(&v.to_ascii_lowercase()).map(|(r, _)| r)
    }

    #[test]
    fn injections_flagged() {
        assert_eq!(risk(r#"{"username":{"$ne":null}}"#), Some(WafRisk::Medium));
        assert_eq!(risk("user[$gt]=&pass[$gt]="), Some(WafRisk::Medium));
        assert_eq!(risk(r#"{"$where":"this.a==this.b"}"#), Some(WafRisk::High));
        assert_eq!(risk(r#"{"q":{"$regex":".*"}}"#), Some(WafRisk::Medium));
        // A benign prefix sharing the operator's bytes must not shadow a real
        // operator later in the value (regression: `find` only saw the first hit).
        assert_eq!(
            risk(r#"$network {"x":{"$ne":null}}"#),
            Some(WafRisk::Medium)
        );
        assert_eq!(
            risk(r#"{"a":"$invalid","b":{"$in":[1]}}"#),
            Some(WafRisk::Medium)
        );
    }

    #[test]
    fn benign_not_flagged() {
        assert!(risk("cost $gt 5 dollars").is_none()); // not operator position
        assert!(risk("the price is $net 5").is_none()); // $ne inside $net
        assert!(risk("$5 and up").is_none());
        assert!(risk("ordinary text without operators").is_none());
    }
}
