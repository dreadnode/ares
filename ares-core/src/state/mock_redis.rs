//! In-memory mock Redis connection for testing state operations.
//!
//! Implements `redis::aio::ConnectionLike` so it can be passed to any function
//! that accepts `&mut impl AsyncCommands`.
//!
//! The connection is `Clone` — clones share the same underlying data store
//! (via `Arc<Mutex<>>`), matching the semantics of `ConnectionManager`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use redis::aio::ConnectionLike;
use redis::{Cmd, ErrorKind, Pipeline, RedisError, RedisResult, Value};

// ---------------------------------------------------------------------------
// Storage types
// ---------------------------------------------------------------------------

enum Stored {
    Str(Vec<u8>),
    Hash(HashMap<Vec<u8>, Vec<u8>>),
    List(VecDeque<Vec<u8>>),
    Set(HashSet<Vec<u8>>),
}

type Data = HashMap<String, Stored>;

// ---------------------------------------------------------------------------
// MockRedisConnection
// ---------------------------------------------------------------------------

/// Minimal in-memory Redis mock that supports the command subset used by
/// `ares-core::state` and `ares-cli::orchestrator::task_queue`.
#[derive(Clone)]
pub struct MockRedisConnection {
    data: Arc<Mutex<Data>>,
}

impl Default for MockRedisConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRedisConnection {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn collect_args(cmd: &Cmd) -> Vec<Vec<u8>> {
        cmd.args_iter()
            .filter_map(|a| match a {
                redis::Arg::Simple(d) => Some(d.to_vec()),
                redis::Arg::Cursor => None,
                _ => None,
            })
            .collect()
    }

    // -- dispatch -----------------------------------------------------------

    fn exec_inner(data: &mut Data, cmd: &Cmd) -> RedisResult<Value> {
        let args = Self::collect_args(cmd);
        if args.is_empty() {
            return Err(RedisError::from((ErrorKind::Io, "empty command")));
        }
        let name = String::from_utf8_lossy(&args[0]).to_uppercase();
        match name.as_str() {
            "GET" => cmd_get(data, &args),
            "SET" => cmd_set(data, &args),
            "SETEX" => cmd_setex(data, &args),
            "SETNX" => cmd_setnx(data, &args),
            "DEL" => cmd_del(data, &args),
            "EXISTS" => cmd_exists(data, &args),
            "EXPIRE" => Ok(Value::Int(1)),
            "HGET" => cmd_hget(data, &args),
            "HSET" => cmd_hset(data, &args),
            "HGETALL" => cmd_hgetall(data, &args),
            "HSETNX" => cmd_hsetnx(data, &args),
            "HDEL" => cmd_hdel(data, &args),
            "HINCRBY" => cmd_hincrby(data, &args),
            "SADD" => cmd_sadd(data, &args),
            "SMEMBERS" => cmd_smembers(data, &args),
            "SREM" => cmd_srem(data, &args),
            "RPUSH" => cmd_rpush(data, &args),
            "LPUSH" => cmd_lpush(data, &args),
            "RPOP" => cmd_rpop(data, &args),
            "LPOP" => cmd_lpop(data, &args),
            "LRANGE" => cmd_lrange(data, &args),
            "LLEN" => cmd_llen(data, &args),
            "BRPOP" => cmd_brpop(data, &args),
            "LSET" => cmd_lset(data, &args),
            "ZADD" => cmd_zadd(data, &args),
            "PUBLISH" => Ok(Value::Int(0)),
            "SCAN" => cmd_scan(data, &args),
            other => Err(RedisError::from((
                ErrorKind::InvalidClientConfig,
                "unsupported mock command",
                other.to_string(),
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionLike impl
// ---------------------------------------------------------------------------

impl ConnectionLike for MockRedisConnection {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> redis::RedisFuture<'a, Value> {
        let mut data = self.data.lock().unwrap();
        let result = Self::exec_inner(&mut data, cmd);
        Box::pin(std::future::ready(result))
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        pipeline: &'a Pipeline,
        offset: usize,
        count: usize,
    ) -> redis::RedisFuture<'a, Vec<Value>> {
        let mut data = self.data.lock().unwrap();
        let mut all_results = Vec::new();
        for cmd in pipeline.cmd_iter() {
            match Self::exec_inner(&mut data, cmd) {
                Ok(v) => all_results.push(v),
                Err(e) => return Box::pin(std::future::ready(Err(e))),
            }
        }
        let slice = all_results.into_iter().skip(offset).take(count).collect();
        Box::pin(std::future::ready(Ok(slice)))
    }

    fn get_db(&self) -> i64 {
        0
    }
}

// ---------------------------------------------------------------------------
// Command implementations (free functions operating on Data)
// ---------------------------------------------------------------------------

fn key(args: &[Vec<u8>], idx: usize) -> String {
    String::from_utf8_lossy(args.get(idx).map(|v| v.as_slice()).unwrap_or_default()).into_owned()
}

fn bulk(v: &[u8]) -> Value {
    Value::BulkString(v.to_vec())
}

// -- string commands --------------------------------------------------------

fn cmd_get(data: &Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    match data.get(&k) {
        Some(Stored::Str(v)) => Ok(bulk(v)),
        _ => Ok(Value::Nil),
    }
}

fn cmd_set(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let v = args.get(2).cloned().unwrap_or_default();

    let mut nx = false;
    let mut i = 3;
    while i < args.len() {
        let flag = String::from_utf8_lossy(&args[i]).to_uppercase();
        match flag.as_str() {
            "EX" | "PX" => i += 2,
            "NX" => {
                nx = true;
                i += 1;
            }
            _ => i += 1,
        }
    }
    if nx && data.contains_key(&k) {
        return Ok(Value::Nil);
    }
    data.insert(k, Stored::Str(v));
    Ok(Value::Okay)
}

fn cmd_setex(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let v = args.get(3).cloned().unwrap_or_default();
    data.insert(k, Stored::Str(v));
    Ok(Value::Okay)
}

fn cmd_setnx(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    if data.contains_key(&k) {
        return Ok(Value::Int(0));
    }
    let v = args.get(2).cloned().unwrap_or_default();
    data.insert(k, Stored::Str(v));
    Ok(Value::Int(1))
}

fn cmd_del(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let mut count = 0i64;
    for a in &args[1..] {
        let k = String::from_utf8_lossy(a).into_owned();
        if data.remove(&k).is_some() {
            count += 1;
        }
    }
    Ok(Value::Int(count))
}

fn cmd_exists(data: &Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    Ok(Value::Int(if data.contains_key(&k) { 1 } else { 0 }))
}

// -- hash commands ----------------------------------------------------------

fn ensure_hash<'a>(data: &'a mut Data, k: &str) -> &'a mut HashMap<Vec<u8>, Vec<u8>> {
    data.entry(k.to_string())
        .or_insert_with(|| Stored::Hash(HashMap::new()));
    match data.get_mut(k) {
        Some(Stored::Hash(h)) => h,
        _ => unreachable!(),
    }
}

fn cmd_hget(data: &Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let field = args.get(2).map(|v| v.as_slice()).unwrap_or_default();
    match data.get(&k) {
        Some(Stored::Hash(h)) => match h.get(field) {
            Some(v) => Ok(bulk(v)),
            None => Ok(Value::Nil),
        },
        _ => Ok(Value::Nil),
    }
}

fn cmd_hset(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let h = ensure_hash(data, &k);
    let mut count = 0i64;
    let mut i = 2;
    while i + 1 < args.len() {
        let field = args[i].clone();
        let value = args[i + 1].clone();
        if h.insert(field, value).is_none() {
            count += 1;
        }
        i += 2;
    }
    Ok(Value::Int(count))
}

fn cmd_hgetall(data: &Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    match data.get(&k) {
        Some(Stored::Hash(h)) => {
            let mut arr = Vec::with_capacity(h.len() * 2);
            for (field, value) in h {
                arr.push(bulk(field));
                arr.push(bulk(value));
            }
            Ok(Value::Array(arr))
        }
        _ => Ok(Value::Array(vec![])),
    }
}

fn cmd_hsetnx(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let field = args.get(2).cloned().unwrap_or_default();
    let value = args.get(3).cloned().unwrap_or_default();
    let h = ensure_hash(data, &k);
    if let std::collections::hash_map::Entry::Vacant(e) = h.entry(field) {
        e.insert(value);
        Ok(Value::Int(1))
    } else {
        Ok(Value::Int(0))
    }
}

fn cmd_hdel(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let mut count = 0i64;
    if let Some(Stored::Hash(h)) = data.get_mut(&k) {
        for field in &args[2..] {
            if h.remove(field.as_slice()).is_some() {
                count += 1;
            }
        }
    }
    Ok(Value::Int(count))
}

fn cmd_hincrby(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let field = args.get(2).cloned().unwrap_or_default();
    let delta: i64 = String::from_utf8_lossy(args.get(3).map(|v| v.as_slice()).unwrap_or(b"1"))
        .parse()
        .unwrap_or(1);
    let h = ensure_hash(data, &k);
    let cur: i64 = h
        .get(&field)
        .and_then(|v| String::from_utf8_lossy(v).parse().ok())
        .unwrap_or(0);
    let new_val = cur + delta;
    h.insert(field, new_val.to_string().into_bytes());
    Ok(Value::Int(new_val))
}

// -- set commands -----------------------------------------------------------

fn ensure_set<'a>(data: &'a mut Data, k: &str) -> &'a mut HashSet<Vec<u8>> {
    data.entry(k.to_string())
        .or_insert_with(|| Stored::Set(HashSet::new()));
    match data.get_mut(k) {
        Some(Stored::Set(s)) => s,
        _ => unreachable!(),
    }
}

fn cmd_sadd(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let s = ensure_set(data, &k);
    let mut count = 0i64;
    for member in &args[2..] {
        if s.insert(member.clone()) {
            count += 1;
        }
    }
    Ok(Value::Int(count))
}

fn cmd_smembers(data: &Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    match data.get(&k) {
        Some(Stored::Set(s)) => {
            let arr: Vec<Value> = s.iter().map(|v| bulk(v)).collect();
            Ok(Value::Array(arr))
        }
        _ => Ok(Value::Array(vec![])),
    }
}

fn cmd_srem(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let mut count = 0i64;
    if let Some(Stored::Set(s)) = data.get_mut(&k) {
        for member in &args[2..] {
            if s.remove(member.as_slice()) {
                count += 1;
            }
        }
    }
    Ok(Value::Int(count))
}

// -- list commands ----------------------------------------------------------

fn ensure_list<'a>(data: &'a mut Data, k: &str) -> &'a mut VecDeque<Vec<u8>> {
    data.entry(k.to_string())
        .or_insert_with(|| Stored::List(VecDeque::new()));
    match data.get_mut(k) {
        Some(Stored::List(l)) => l,
        _ => unreachable!(),
    }
}

fn cmd_rpush(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let l = ensure_list(data, &k);
    for v in &args[2..] {
        l.push_back(v.clone());
    }
    Ok(Value::Int(l.len() as i64))
}

fn cmd_lpush(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let l = ensure_list(data, &k);
    for v in &args[2..] {
        l.push_front(v.clone());
    }
    Ok(Value::Int(l.len() as i64))
}

fn cmd_rpop(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    match data.get_mut(&k) {
        Some(Stored::List(l)) => match l.pop_back() {
            Some(v) => Ok(bulk(&v)),
            None => Ok(Value::Nil),
        },
        _ => Ok(Value::Nil),
    }
}

fn cmd_lpop(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    match data.get_mut(&k) {
        Some(Stored::List(l)) => match l.pop_front() {
            Some(v) => Ok(bulk(&v)),
            None => Ok(Value::Nil),
        },
        _ => Ok(Value::Nil),
    }
}

fn cmd_lrange(data: &Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let start: i64 = String::from_utf8_lossy(args.get(2).map(|v| v.as_slice()).unwrap_or(b"0"))
        .parse()
        .unwrap_or(0);
    let stop: i64 = String::from_utf8_lossy(args.get(3).map(|v| v.as_slice()).unwrap_or(b"-1"))
        .parse()
        .unwrap_or(-1);

    match data.get(&k) {
        Some(Stored::List(l)) => {
            let len = l.len() as i64;
            let s = if start < 0 {
                (len + start).max(0) as usize
            } else {
                start as usize
            };
            let e = if stop < 0 {
                (len + stop).max(0) as usize
            } else {
                stop as usize
            };
            let arr: Vec<Value> = l
                .iter()
                .skip(s)
                .take(if e >= s { e - s + 1 } else { 0 })
                .map(|v| bulk(v))
                .collect();
            Ok(Value::Array(arr))
        }
        _ => Ok(Value::Array(vec![])),
    }
}

fn cmd_llen(data: &Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    match data.get(&k) {
        Some(Stored::List(l)) => Ok(Value::Int(l.len() as i64)),
        _ => Ok(Value::Int(0)),
    }
}

fn cmd_brpop(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let keys_end = args.len().saturating_sub(1);
    for a in &args[1..keys_end.max(1)] {
        let k = String::from_utf8_lossy(a).into_owned();
        if let Some(Stored::List(l)) = data.get_mut(&k) {
            if let Some(v) = l.pop_back() {
                return Ok(Value::Array(vec![bulk(a), bulk(&v)]));
            }
        }
    }
    Ok(Value::Nil)
}

// -- scan -------------------------------------------------------------------

fn cmd_lset(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let k = key(args, 1);
    let index: i64 = String::from_utf8_lossy(args.get(2).map(|v| v.as_slice()).unwrap_or(b"0"))
        .parse()
        .unwrap_or(0);
    let value = args.get(3).cloned().unwrap_or_default();
    match data.get_mut(&k) {
        Some(Stored::List(l)) => {
            let idx = if index < 0 {
                (l.len() as i64 + index).max(0) as usize
            } else {
                index as usize
            };
            if idx < l.len() {
                l[idx] = value;
                Ok(Value::Okay)
            } else {
                Err(RedisError::from((ErrorKind::Io, "index out of range")))
            }
        }
        _ => Err(RedisError::from((ErrorKind::Io, "no such key"))),
    }
}

fn cmd_zadd(data: &mut Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    // ZADD key score member [score member ...]
    // Stored as a List of (score, member) pairs — sufficient for basic tests
    let k = key(args, 1);
    let l = ensure_list(data, &k);
    let mut count = 0i64;
    let mut i = 2;
    while i + 1 < args.len() {
        // args[i] = score, args[i+1] = member
        let member = args[i + 1].clone();
        l.push_back(member);
        count += 1;
        i += 2;
    }
    Ok(Value::Int(count))
}

fn cmd_scan(data: &Data, args: &[Vec<u8>]) -> RedisResult<Value> {
    let mut pattern: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        let flag = String::from_utf8_lossy(&args[i]).to_uppercase();
        if flag == "MATCH" {
            pattern = args
                .get(i + 1)
                .map(|v| String::from_utf8_lossy(v).into_owned());
            i += 2;
        } else {
            i += 2;
        }
    }

    let keys: Vec<Value> = data
        .keys()
        .filter(|k| match &pattern {
            Some(p) => glob_match(p, k),
            None => true,
        })
        .map(|k| Value::BulkString(k.as_bytes().to_vec()))
        .collect();

    Ok(Value::Array(vec![
        Value::BulkString(b"0".to_vec()),
        Value::Array(keys),
    ]))
}

// ---------------------------------------------------------------------------
// Minimal glob matching (supports only `*` wildcard segments)
// ---------------------------------------------------------------------------

fn glob_match(pattern: &str, input: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == input;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match input[pos..].find(part) {
            Some(idx) => {
                if i == 0 && idx != 0 {
                    return false;
                }
                pos += idx + part.len();
            }
            None => return false,
        }
    }
    if !pattern.ends_with('*') {
        return pos == input.len();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn glob_match_wildcard() {
        assert!(glob_match("ares:op:*:meta", "ares:op:op-123:meta"));
        assert!(!glob_match("ares:op:*:meta", "ares:op:op-123:creds"));
        assert!(glob_match("ares:lock:*", "ares:lock:op-1"));
        assert!(glob_match("ares:op:op-1:*", "ares:op:op-1:meta"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn glob_match_prefix() {
        assert!(glob_match("ares:task_status:*", "ares:task_status:abc"));
        assert!(!glob_match("ares:task_status:*", "other:task_status:abc"));
    }

    #[test]
    fn clone_shares_data() {
        use redis::AsyncCommands;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn1 = MockRedisConnection::new();
            let mut conn2 = conn1.clone();
            let _: () = conn1.set("key1", "value1").await.unwrap();
            let val: String = conn2.get("key1").await.unwrap();
            assert_eq!(val, "value1");
        });
    }

    #[test]
    fn pipeline_executes_commands() {
        use redis::AsyncCommands;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.lpush("q:a", "result-a").await.unwrap();
            let _: () = conn.lpush("q:b", "result-b").await.unwrap();

            let mut pipe = redis::pipe();
            pipe.cmd("RPOP").arg("q:a");
            pipe.cmd("RPOP").arg("q:b");
            pipe.cmd("RPOP").arg("q:missing");

            let results: Vec<Option<String>> = pipe.query_async(&mut conn).await.unwrap();
            assert_eq!(results.len(), 3);
            assert_eq!(results[0], Some("result-a".to_string()));
            assert_eq!(results[1], Some("result-b".to_string()));
            assert_eq!(results[2], None);
        });
    }

    // -- string commands -------------------------------------------------------

    #[test]
    fn setex_stores_value() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = redis::cmd("SETEX")
                .arg("k")
                .arg(60)
                .arg("val")
                .query_async(&mut conn)
                .await
                .unwrap();
            let v: String = conn.get("k").await.unwrap();
            assert_eq!(v, "val");
        });
    }

    #[test]
    fn setnx_only_sets_if_absent() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let r1: i64 = redis::cmd("SETNX")
                .arg("k")
                .arg("first")
                .query_async(&mut conn)
                .await
                .unwrap();
            assert_eq!(r1, 1);
            let r2: i64 = redis::cmd("SETNX")
                .arg("k")
                .arg("second")
                .query_async(&mut conn)
                .await
                .unwrap();
            assert_eq!(r2, 0);
            let v: String = conn.get("k").await.unwrap();
            assert_eq!(v, "first");
        });
    }

    #[test]
    fn set_with_nx_flag() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.set("k", "original").await.unwrap();
            // SET with NX should fail when key exists
            let r: Value = redis::cmd("SET")
                .arg("k")
                .arg("new")
                .arg("NX")
                .query_async(&mut conn)
                .await
                .unwrap();
            assert_eq!(r, Value::Nil);
            let v: String = conn.get("k").await.unwrap();
            assert_eq!(v, "original");
        });
    }

    #[test]
    fn del_removes_keys() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.set("a", "1").await.unwrap();
            let _: () = conn.set("b", "2").await.unwrap();
            let count: i64 = conn.del(&["a", "b", "nonexistent"]).await.unwrap();
            assert_eq!(count, 2);
            let v: Option<String> = conn.get("a").await.unwrap();
            assert!(v.is_none());
        });
    }

    #[test]
    fn exists_checks_key() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let e1: bool = conn.exists("missing").await.unwrap();
            assert!(!e1);
            let _: () = conn.set("present", "yes").await.unwrap();
            let e2: bool = conn.exists("present").await.unwrap();
            assert!(e2);
        });
    }

    // -- hash commands ---------------------------------------------------------

    #[test]
    fn hset_and_hget() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.hset("myhash", "field1", "value1").await.unwrap();
            let v: String = conn.hget("myhash", "field1").await.unwrap();
            assert_eq!(v, "value1");
            // Missing field
            let missing: Option<String> = conn.hget("myhash", "nope").await.unwrap();
            assert!(missing.is_none());
            // Missing key
            let no_key: Option<String> = conn.hget("nohash", "f").await.unwrap();
            assert!(no_key.is_none());
        });
    }

    #[test]
    fn hgetall_returns_all_fields() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.hset("h", "a", "1").await.unwrap();
            let _: () = conn.hset("h", "b", "2").await.unwrap();
            let r: Value = redis::cmd("HGETALL")
                .arg("h")
                .query_async(&mut conn)
                .await
                .unwrap();
            match r {
                Value::Array(arr) => assert_eq!(arr.len(), 4), // 2 field-value pairs
                _ => panic!("Expected array from HGETALL"),
            }
            // Empty hash
            let r2: Value = redis::cmd("HGETALL")
                .arg("nope")
                .query_async(&mut conn)
                .await
                .unwrap();
            match r2 {
                Value::Array(arr) => assert!(arr.is_empty()),
                _ => panic!("Expected empty array"),
            }
        });
    }

    #[test]
    fn hsetnx_only_sets_if_field_absent() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let r1: bool = conn.hset_nx("h", "f", "first").await.unwrap();
            assert!(r1);
            let r2: bool = conn.hset_nx("h", "f", "second").await.unwrap();
            assert!(!r2);
            let v: String = conn.hget("h", "f").await.unwrap();
            assert_eq!(v, "first");
        });
    }

    #[test]
    fn hdel_removes_fields() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.hset("h", "a", "1").await.unwrap();
            let _: () = conn.hset("h", "b", "2").await.unwrap();
            let count: i64 = conn.hdel("h", "a").await.unwrap();
            assert_eq!(count, 1);
            let r: Value = redis::cmd("HGETALL")
                .arg("h")
                .query_async(&mut conn)
                .await
                .unwrap();
            match r {
                Value::Array(arr) => assert_eq!(arr.len(), 2), // 1 remaining field-value pair
                _ => panic!("Expected array"),
            }
            // HDEL on missing key
            let zero: i64 = conn.hdel("nope", "f").await.unwrap();
            assert_eq!(zero, 0);
        });
    }

    #[test]
    fn hincrby_increments() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let v1: i64 = conn.hincr("h", "counter", 5).await.unwrap();
            assert_eq!(v1, 5);
            let v2: i64 = conn.hincr("h", "counter", 3).await.unwrap();
            assert_eq!(v2, 8);
            let v3: i64 = conn.hincr("h", "counter", -2).await.unwrap();
            assert_eq!(v3, 6);
        });
    }

    // -- set commands ----------------------------------------------------------

    #[test]
    fn sadd_and_smembers() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let added: i64 = conn.sadd("s", "a").await.unwrap();
            assert_eq!(added, 1);
            let dup: i64 = conn.sadd("s", "a").await.unwrap();
            assert_eq!(dup, 0);
            let _: () = conn.sadd("s", "b").await.unwrap();
            let members: HashSet<String> = conn.smembers("s").await.unwrap();
            assert_eq!(members.len(), 2);
            assert!(members.contains("a"));
            assert!(members.contains("b"));
            // Empty set
            let empty: HashSet<String> = conn.smembers("nope").await.unwrap();
            assert!(empty.is_empty());
        });
    }

    #[test]
    fn srem_removes_members() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.sadd("s", "a").await.unwrap();
            let _: () = conn.sadd("s", "b").await.unwrap();
            let removed: i64 = conn.srem("s", "a").await.unwrap();
            assert_eq!(removed, 1);
            let members: HashSet<String> = conn.smembers("s").await.unwrap();
            assert_eq!(members.len(), 1);
            // SREM on missing set
            let zero: i64 = conn.srem("nope", "x").await.unwrap();
            assert_eq!(zero, 0);
        });
    }

    // -- list commands ---------------------------------------------------------

    #[test]
    fn rpush_and_lrange() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.rpush("list", "a").await.unwrap();
            let _: () = conn.rpush("list", "b").await.unwrap();
            let _: () = conn.rpush("list", "c").await.unwrap();
            let all: Vec<String> = conn.lrange("list", 0, -1).await.unwrap();
            assert_eq!(all, vec!["a", "b", "c"]);
            let sub: Vec<String> = conn.lrange("list", 1, 2).await.unwrap();
            assert_eq!(sub, vec!["b", "c"]);
            // Empty list
            let empty: Vec<String> = conn.lrange("nope", 0, -1).await.unwrap();
            assert!(empty.is_empty());
        });
    }

    #[test]
    fn lrange_negative_indices() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.rpush("l", "a").await.unwrap();
            let _: () = conn.rpush("l", "b").await.unwrap();
            let _: () = conn.rpush("l", "c").await.unwrap();
            // Last 2 elements
            let last2: Vec<String> = conn.lrange("l", -2, -1).await.unwrap();
            assert_eq!(last2, vec!["b", "c"]);
        });
    }

    #[test]
    fn lpop_removes_from_front() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.rpush("l", "first").await.unwrap();
            let _: () = conn.rpush("l", "second").await.unwrap();
            let v: String = conn.lpop("l", None).await.unwrap();
            assert_eq!(v, "first");
            // Pop from empty
            let empty: Option<String> = conn.lpop("empty", None).await.unwrap();
            assert!(empty.is_none());
        });
    }

    #[test]
    fn rpop_removes_from_back() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.rpush("l", "first").await.unwrap();
            let _: () = conn.rpush("l", "second").await.unwrap();
            let v: String = conn.rpop("l", None).await.unwrap();
            assert_eq!(v, "second");
            // Pop on empty list
            let empty: Option<String> = conn.rpop("empty", None).await.unwrap();
            assert!(empty.is_none());
        });
    }

    #[test]
    fn llen_returns_length() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let empty_len: i64 = conn.llen("nope").await.unwrap();
            assert_eq!(empty_len, 0);
            let _: () = conn.rpush("l", "a").await.unwrap();
            let _: () = conn.rpush("l", "b").await.unwrap();
            let len: i64 = conn.llen("l").await.unwrap();
            assert_eq!(len, 2);
        });
    }

    #[test]
    fn lset_updates_element() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.rpush("l", "a").await.unwrap();
            let _: () = conn.rpush("l", "b").await.unwrap();
            let _: () = conn.lset("l", 1, "B").await.unwrap();
            let all: Vec<String> = conn.lrange("l", 0, -1).await.unwrap();
            assert_eq!(all, vec!["a", "B"]);
        });
    }

    #[test]
    fn lset_negative_index() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.rpush("l", "a").await.unwrap();
            let _: () = conn.rpush("l", "b").await.unwrap();
            let _: () = conn.lset("l", -1, "Z").await.unwrap();
            let all: Vec<String> = conn.lrange("l", 0, -1).await.unwrap();
            assert_eq!(all, vec!["a", "Z"]);
        });
    }

    #[test]
    fn lset_out_of_range_errors() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            // LSET on missing key
            let r: RedisResult<()> = redis::cmd("LSET")
                .arg("nope")
                .arg(0)
                .arg("v")
                .query_async(&mut conn)
                .await;
            assert!(r.is_err());
        });
    }

    #[test]
    fn brpop_pops_from_first_non_empty() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.rpush("q2", "item").await.unwrap();
            // BRPOP q1 q2 0 — q1 is empty, should pop from q2
            let r: Value = redis::cmd("BRPOP")
                .arg("q1")
                .arg("q2")
                .arg(0)
                .query_async(&mut conn)
                .await
                .unwrap();
            match r {
                Value::Array(arr) => {
                    assert_eq!(arr.len(), 2);
                }
                _ => panic!("Expected array from BRPOP"),
            }
        });
    }

    #[test]
    fn brpop_returns_nil_when_all_empty() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let r: Value = redis::cmd("BRPOP")
                .arg("empty1")
                .arg("empty2")
                .arg(0)
                .query_async(&mut conn)
                .await
                .unwrap();
            assert_eq!(r, Value::Nil);
        });
    }

    // -- sorted set commands ---------------------------------------------------

    #[test]
    fn zadd_adds_members() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let count: i64 = redis::cmd("ZADD")
                .arg("zs")
                .arg(1.0f64)
                .arg("a")
                .arg(2.0f64)
                .arg("b")
                .query_async(&mut conn)
                .await
                .unwrap();
            assert_eq!(count, 2);
        });
    }

    // -- scan ------------------------------------------------------------------

    #[test]
    fn scan_returns_matching_keys() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.set("ares:op:1:meta", "m").await.unwrap();
            let _: () = conn.set("ares:op:1:creds", "c").await.unwrap();
            let _: () = conn.set("other:key", "x").await.unwrap();
            let r: Value = redis::cmd("SCAN")
                .arg(0)
                .arg("MATCH")
                .arg("ares:op:*")
                .query_async(&mut conn)
                .await
                .unwrap();
            match r {
                Value::Array(arr) => {
                    assert_eq!(arr.len(), 2); // cursor + keys array
                    if let Value::Array(ref keys) = arr[1] {
                        assert_eq!(keys.len(), 2);
                    }
                }
                _ => panic!("Expected array from SCAN"),
            }
        });
    }

    #[test]
    fn scan_no_match_returns_all() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let _: () = conn.set("a", "1").await.unwrap();
            let _: () = conn.set("b", "2").await.unwrap();
            let r: Value = redis::cmd("SCAN")
                .arg(0)
                .query_async(&mut conn)
                .await
                .unwrap();
            match r {
                Value::Array(arr) => {
                    if let Value::Array(ref keys) = arr[1] {
                        assert_eq!(keys.len(), 2);
                    }
                }
                _ => panic!("Expected array from SCAN"),
            }
        });
    }

    // -- unsupported command ---------------------------------------------------

    #[test]
    fn unsupported_command_errors() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::new();
            let r: RedisResult<Value> = redis::cmd("FLUSHALL").query_async(&mut conn).await;
            assert!(r.is_err());
        });
    }

    // -- get_db ----------------------------------------------------------------

    #[test]
    fn get_db_returns_zero() {
        let conn = MockRedisConnection::new();
        assert_eq!(conn.get_db(), 0);
    }

    // -- default ---------------------------------------------------------------

    #[test]
    fn default_creates_empty() {
        use redis::AsyncCommands;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = MockRedisConnection::default();
            let v: Option<String> = conn.get("anything").await.unwrap();
            assert!(v.is_none());
        });
    }
}
