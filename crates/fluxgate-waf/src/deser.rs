//! Insecure deserialization. Flags the distinctive signatures of serialized
//! object streams (Java / PHP / Python / .NET) that carry RCE gadgets. Input is
//! the shared lowercased view.

use fluxgate_core::WafRisk;

pub fn detect(lower: &str) -> Option<(WafRisk, String)> {
    // Java serialized stream — base64 of the 0xACED0005 magic ("rO0AB…"), the raw
    // hex magic, or the stream class name.
    if lower.contains("ro0ab") || lower.contains("aced0005") || lower.contains("objectinputstream")
    {
        return Some((WafRisk::High, "java_serialized".into()));
    }
    // Python pickle RCE gadgets (the `__reduce__` / global-import opcodes that
    // actually drive code execution — not the generic list/dict opcodes, which
    // appear in every pickle and would false-positive on benign text).
    if lower.contains("__reduce__")
        || lower.contains("__reduce_ex__")
        || lower.contains("c__builtin__")
        || lower.contains("cposix")
    {
        return Some((WafRisk::High, "python_pickle".into()));
    }
    // Ruby YAML / Node `node-serialize` RCE markers.
    if lower.contains("!ruby/object") || lower.contains("_$$nd_func$$_") {
        return Some((WafRisk::High, "ruby_or_node_serialized".into()));
    }
    // .NET typed-object gadgets (Json.NET `TypeNameHandling` / `__type`).
    if (lower.contains("$type") || lower.contains("__type") || lower.contains("typeobject"))
        && lower.contains("system.")
    {
        return Some((WafRisk::High, "dotnet_typed".into()));
    }
    // PHP serialized object/array: `O:<digits>:"<class>"` or `a:<digits>:{`.
    if php_serialized(lower.as_bytes()) {
        return Some((WafRisk::High, "php_serialized".into()));
    }
    None
}

/// `[oa]:<digits>:` immediately followed by `"` (object class) or `{` (array) —
/// the PHP `serialize()` shape. A bare `a:1 ratio` in prose has a space, not `:`,
/// after the number, so it isn't matched.
fn php_serialized(b: &[u8]) -> bool {
    let mut i = 0;
    while i + 2 < b.len() {
        if (b[i] == b'o' || b[i] == b'a') && b[i + 1] == b':' && b[i + 2].is_ascii_digit() {
            let mut j = i + 2;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j + 1 < b.len() && b[j] == b':' && matches!(b[j + 1], b'"' | b'{') {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risk(v: &str) -> Option<WafRisk> {
        detect(&v.to_ascii_lowercase()).map(|(r, _)| r)
    }

    #[test]
    fn serialized_streams_flagged() {
        assert_eq!(risk("rO0ABXNyABFqYXZhLnV0aWwu"), Some(WafRisk::High)); // Java
        assert_eq!(
            risk(r#"O:8:"stdClass":1:{s:3:"cmd";}"#),
            Some(WafRisk::High)
        ); // PHP
        assert_eq!(risk("a:2:{i:0;s:2:\"hi\";}"), Some(WafRisk::High)); // PHP array
        assert_eq!(risk("c__builtin__\neval\n(S'1'\ntR."), Some(WafRisk::High));
        // pickle
    }

    #[test]
    fn benign_not_flagged() {
        assert!(risk("a:1 ratio of items").is_none());
        assert!(risk("O:30 the meeting starts").is_none());
        assert!(risk("ordinary text").is_none());
        assert!(risk("the type is system administrator").is_none()); // no $type
    }
}
