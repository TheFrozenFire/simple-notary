use serde_json::Value;

/// Checks whether `subset` is a valid filtered subset of `superset`.
///
/// Filtering primitives:
/// - **Object key removal** — any key present in the superset may be omitted.
/// - **Null replacement** — any value (including array elements) may be replaced with `null`.
///
/// Array element *removal* is not allowed — arrays must keep the same length
/// so positional correspondence is preserved.
pub fn is_json_subset(subset: &Value, superset: &Value) -> bool {
    match (subset, superset) {
        // Null replaces anything (redaction).
        (Value::Null, _) => true,

        // Scalars must match exactly.
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,

        // Arrays must have the same length; each element is checked recursively.
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(s, p)| is_json_subset(s, p))
        }

        // Objects: every key in subset must exist in superset with a valid sub-value.
        (Value::Object(a), Value::Object(b)) => {
            a.iter().all(|(key, val)| {
                b.get(key)
                    .map_or(false, |sup_val| is_json_subset(val, sup_val))
            })
        }

        // Type mismatch or non-null subset where superset is a different type.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identity_is_subset() {
        let v = json!({"request": {"headers": [["Host", "example.com"]]}, "response": {"body": "OK"}});
        assert!(is_json_subset(&v, &v));
    }

    #[test]
    fn key_removal_passes() {
        let superset = json!({"a": 1, "b": 2, "c": 3});
        let subset = json!({"a": 1});
        assert!(is_json_subset(&subset, &superset));
    }

    #[test]
    fn null_replacement_passes() {
        let superset = json!({"a": 1, "b": "secret"});
        let subset = json!({"a": 1, "b": null});
        assert!(is_json_subset(&subset, &superset));
    }

    #[test]
    fn scalar_change_rejected() {
        let superset = json!({"a": 1});
        let subset = json!({"a": 2});
        assert!(!is_json_subset(&subset, &superset));
    }

    #[test]
    fn key_addition_rejected() {
        let superset = json!({"a": 1});
        let subset = json!({"a": 1, "b": 2});
        assert!(!is_json_subset(&subset, &superset));
    }

    #[test]
    fn array_length_mismatch_rejected() {
        let superset = json!([1, 2, 3]);
        let subset = json!([1, 2]);
        assert!(!is_json_subset(&subset, &superset));
    }

    #[test]
    fn type_mismatch_rejected() {
        let superset = json!({"a": "string"});
        let subset = json!({"a": 42});
        assert!(!is_json_subset(&subset, &superset));
    }

    #[test]
    fn deep_nesting_with_null_replacement() {
        let superset = json!({
            "request": {
                "headers": [["Host", "example.com"], ["Cookie", "session=abc"]],
                "body": "payload"
            }
        });
        let subset = json!({
            "request": {
                "headers": [["Host", "example.com"], null]
            }
        });
        assert!(is_json_subset(&subset, &superset));
    }

    #[test]
    fn empty_object_is_subset_of_any_object() {
        let superset = json!({"a": 1, "b": [2, 3]});
        let subset = json!({});
        assert!(is_json_subset(&subset, &superset));
    }

    #[test]
    fn full_null_array_is_subset() {
        let superset = json!(["hello", 42]);
        let subset = json!([null, null]);
        assert!(is_json_subset(&subset, &superset));
    }
}
