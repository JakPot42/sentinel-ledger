//! Canonical form, docs/SPEC.md section 7.1.
//!
//! Must produce exactly the bytes Python's
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)` produces,
//! because the verifier re-serialises every record and compares. serde_json's own writer
//! is not used: it emits non-ASCII characters raw, and Python escapes them.

use serde_json::Value;

/// Canonical text of `v`. Fails on a float, a boolean, or an integer outside i64:
/// the specification allows integers, strings, null, arrays and objects only.
pub fn canonical(v: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_value(v, &mut out)?;
    Ok(out)
}

fn write_value(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(_) => return Err("boolean value".to_string()),
        Value::Number(n) => match n.as_i64() {
            Some(i) => out.push_str(&i.to_string()),
            None => return Err(format!("{n} is not an integer in the 64-bit signed range")),
        },
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Rust compares strings by UTF-8 bytes, which is code point order: the
            // order Python's sort_keys uses.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[*key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                // Everything outside printable ASCII, as UTF-16 code units.
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Expected strings were produced with Python 3.14:
    // json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    #[test]
    fn keys_are_sorted_and_there_is_no_whitespace() {
        let v = json!({"b": 1, "a": [1, 2, {"z": null, "y": "x"}]});
        assert_eq!(canonical(&v).unwrap(), r#"{"a":[1,2,{"y":"x","z":null}],"b":1}"#);
    }

    #[test]
    fn strings_are_escaped_the_way_python_escapes_them() {
        let v = json!("a\"b\\c\n\t\u{01}\u{7f}é\u{1F600}");
        assert_eq!(
            canonical(&v).unwrap(),
            r#""a\"b\\c\n\t\u0001\u007f\u00e9\ud83d\ude00""#
        );
    }

    #[test]
    fn negative_and_large_integers() {
        let v = json!([-50, 0, 9223372036854775807i64]);
        assert_eq!(canonical(&v).unwrap(), "[-50,0,9223372036854775807]");
    }

    #[test]
    fn floats_and_booleans_are_rejected() {
        assert!(canonical(&json!({"speed": 1.5})).is_err());
        assert!(canonical(&json!({"speed": 1.0})).is_err());
        assert!(canonical(&json!({"on": true})).is_err());
        assert!(canonical(&json!(18446744073709551615u64)).is_err());
    }
}
