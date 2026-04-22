use serde_json::Value;

/// Extract a required string field from JSON arguments.
pub fn required_str<'a>(args: &'a Value, field: &str) -> anyhow::Result<&'a str> {
    args.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {field}"))
}

/// Extract an optional string field from JSON arguments.
pub fn optional_str<'a>(args: &'a Value, field: &str) -> Option<&'a str> {
    args.get(field).and_then(Value::as_str)
}

/// Extract an optional integer field from JSON arguments.
pub fn optional_i64(args: &Value, field: &str) -> Option<i64> {
    args.get(field).and_then(Value::as_i64)
}

/// Extract an optional boolean field from JSON arguments.
pub fn optional_bool(args: &Value, field: &str) -> Option<bool> {
    args.get(field).and_then(Value::as_bool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn required_str_present() {
        let args = json!({"name": "alice"});
        let val = required_str(&args, "name").unwrap();
        assert_eq!(val, "alice");
    }

    #[test]
    fn required_str_missing_returns_error() {
        let args = json!({"other": "value"});
        let err = required_str(&args, "name").unwrap_err();
        assert!(
            err.to_string().contains("missing required argument: name"),
            "got: {err}"
        );
    }

    #[test]
    fn required_str_wrong_type_returns_error() {
        let args = json!({"count": 42});
        let err = required_str(&args, "count").unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }

    #[test]
    fn optional_str_present() {
        let args = json!({"host": "192.168.58.1"});
        assert_eq!(optional_str(&args, "host"), Some("192.168.58.1"));
    }

    #[test]
    fn optional_str_missing() {
        let args = json!({});
        assert_eq!(optional_str(&args, "host"), None);
    }

    #[test]
    fn optional_str_wrong_type() {
        let args = json!({"port": 8080});
        assert_eq!(optional_str(&args, "port"), None);
    }

    #[test]
    fn optional_i64_present() {
        let args = json!({"port": 445});
        assert_eq!(optional_i64(&args, "port"), Some(445));
    }

    #[test]
    fn optional_i64_missing() {
        let args = json!({});
        assert_eq!(optional_i64(&args, "port"), None);
    }

    #[test]
    fn optional_i64_wrong_type() {
        let args = json!({"port": "not_a_number"});
        assert_eq!(optional_i64(&args, "port"), None);
    }

    #[test]
    fn optional_bool_present_true() {
        let args = json!({"verbose": true});
        assert_eq!(optional_bool(&args, "verbose"), Some(true));
    }

    #[test]
    fn optional_bool_present_false() {
        let args = json!({"verbose": false});
        assert_eq!(optional_bool(&args, "verbose"), Some(false));
    }

    #[test]
    fn optional_bool_missing() {
        let args = json!({});
        assert_eq!(optional_bool(&args, "verbose"), None);
    }

    #[test]
    fn optional_bool_wrong_type() {
        let args = json!({"verbose": "yes"});
        assert_eq!(optional_bool(&args, "verbose"), None);
    }
}
