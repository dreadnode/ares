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
