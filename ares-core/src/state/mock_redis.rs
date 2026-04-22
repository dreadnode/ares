//! In-memory mock Redis connection for testing state operations.
//!
//! Implements `redis::aio::ConnectionLike` so it can be passed to any function
//! that accepts `&mut impl AsyncCommands`.

use std::collections::{HashMap, HashSet, VecDeque};

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

// ---------------------------------------------------------------------------
// MockRedisConnection
// ---------------------------------------------------------------------------

/// Minimal in-memory Redis mock that supports the command subset used by
/// `ares-core::state`.
pub struct MockRedisConnection {
    data: HashMap<String, Stored>,
}

impl MockRedisConnection {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    // -- helpers ------------------------------------------------------------

    fn key(args: &[Vec<u8>], idx: usize) -> String {
        String::from_utf8_lossy(args.get(idx).map(|v| v.as_slice()).unwrap_or_default())
            .into_owned()
    }

    fn bulk(v: &[u8]) -> Value {
        Value::BulkString(v.to_vec())
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

    fn exec(&mut self, cmd: &Cmd) -> RedisResult<Value> {
        let args = Self::collect_args(cmd);
        if args.is_empty() {
            return Err(RedisError::from((ErrorKind::Io, "empty command")));
        }
        let name = String::from_utf8_lossy(&args[0]).to_uppercase();
        match name.as_str() {
            "GET" => self.cmd_get(&args),
            "SET" => self.cmd_set(&args),
            "SETEX" => self.cmd_setex(&args),
            "SETNX" => self.cmd_setnx(&args),
            "DEL" => self.cmd_del(&args),
            "EXISTS" => self.cmd_exists(&args),
            "EXPIRE" => self.cmd_expire(&args),
            "HGET" => self.cmd_hget(&args),
            "HSET" => self.cmd_hset(&args),
            "HGETALL" => self.cmd_hgetall(&args),
            "HSETNX" => self.cmd_hsetnx(&args),
            "HDEL" => self.cmd_hdel(&args),
            "HINCRBY" => self.cmd_hincrby(&args),
            "SADD" => self.cmd_sadd(&args),
            "SMEMBERS" => self.cmd_smembers(&args),
            "SREM" => self.cmd_srem(&args),
            "RPUSH" => self.cmd_rpush(&args),
            "LPUSH" => self.cmd_lpush(&args),
            "RPOP" => self.cmd_rpop(&args),
            "LPOP" => self.cmd_lpop(&args),
            "LRANGE" => self.cmd_lrange(&args),
            "LLEN" => self.cmd_llen(&args),
            "BRPOP" => self.cmd_brpop(&args),
            "PUBLISH" => Ok(Value::Int(0)),
            "SCAN" => self.cmd_scan(&args),
            other => Err(RedisError::from((
                ErrorKind::InvalidClientConfig,
                "unsupported mock command",
                other.to_string(),
            ))),
        }
    }

    // -- string commands ----------------------------------------------------

    fn cmd_get(&self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        match self.data.get(&k) {
            Some(Stored::Str(v)) => Ok(Self::bulk(v)),
            _ => Ok(Value::Nil),
        }
    }

    fn cmd_set(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        // SET key value [EX seconds] [NX]
        let k = Self::key(args, 1);
        let v = args.get(2).cloned().unwrap_or_default();

        let mut nx = false;
        let mut i = 3;
        while i < args.len() {
            let flag = String::from_utf8_lossy(&args[i]).to_uppercase();
            match flag.as_str() {
                "EX" | "PX" => {
                    i += 2;
                } // skip ttl value
                "NX" => {
                    nx = true;
                    i += 1;
                }
                _ => i += 1,
            }
        }
        if nx && self.data.contains_key(&k) {
            return Ok(Value::Nil);
        }
        self.data.insert(k, Stored::Str(v));
        Ok(Value::Okay)
    }

    fn cmd_setex(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        // SETEX key seconds value
        let k = Self::key(args, 1);
        // args[2] = seconds (ignored in mock)
        let v = args.get(3).cloned().unwrap_or_default();
        self.data.insert(k, Stored::Str(v));
        Ok(Value::Okay)
    }

    fn cmd_setnx(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        if self.data.contains_key(&k) {
            return Ok(Value::Int(0));
        }
        let v = args.get(2).cloned().unwrap_or_default();
        self.data.insert(k, Stored::Str(v));
        Ok(Value::Int(1))
    }

    fn cmd_del(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let mut count = 0i64;
        for a in &args[1..] {
            let k = String::from_utf8_lossy(a).into_owned();
            if self.data.remove(&k).is_some() {
                count += 1;
            }
        }
        Ok(Value::Int(count))
    }

    fn cmd_exists(&self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        Ok(Value::Int(if self.data.contains_key(&k) { 1 } else { 0 }))
    }

    fn cmd_expire(&self, _args: &[Vec<u8>]) -> RedisResult<Value> {
        // TTL tracking not needed for tests — just return 1 if key exists.
        Ok(Value::Int(1))
    }

    // -- hash commands ------------------------------------------------------

    fn ensure_hash(&mut self, k: &str) -> &mut HashMap<Vec<u8>, Vec<u8>> {
        self.data
            .entry(k.to_string())
            .or_insert_with(|| Stored::Hash(HashMap::new()));
        match self.data.get_mut(k) {
            Some(Stored::Hash(h)) => h,
            _ => unreachable!(),
        }
    }

    fn cmd_hget(&self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        let field = args.get(2).map(|v| v.as_slice()).unwrap_or_default();
        match self.data.get(&k) {
            Some(Stored::Hash(h)) => match h.get(field) {
                Some(v) => Ok(Self::bulk(v)),
                None => Ok(Value::Nil),
            },
            _ => Ok(Value::Nil),
        }
    }

    fn cmd_hset(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        // HSET key field value [field value ...]
        let k = Self::key(args, 1);
        let h = self.ensure_hash(&k);
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

    fn cmd_hgetall(&self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        match self.data.get(&k) {
            Some(Stored::Hash(h)) => {
                let mut arr = Vec::with_capacity(h.len() * 2);
                for (field, value) in h {
                    arr.push(Self::bulk(field));
                    arr.push(Self::bulk(value));
                }
                Ok(Value::Array(arr))
            }
            _ => Ok(Value::Array(vec![])),
        }
    }

    fn cmd_hsetnx(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        let field = args.get(2).cloned().unwrap_or_default();
        let value = args.get(3).cloned().unwrap_or_default();
        let h = self.ensure_hash(&k);
        if let std::collections::hash_map::Entry::Vacant(e) = h.entry(field) {
            e.insert(value);
            Ok(Value::Int(1))
        } else {
            Ok(Value::Int(0))
        }
    }

    fn cmd_hdel(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        let mut count = 0i64;
        if let Some(Stored::Hash(h)) = self.data.get_mut(&k) {
            for field in &args[2..] {
                if h.remove(field.as_slice()).is_some() {
                    count += 1;
                }
            }
        }
        Ok(Value::Int(count))
    }

    fn cmd_hincrby(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        let field = args.get(2).cloned().unwrap_or_default();
        let delta: i64 = String::from_utf8_lossy(args.get(3).map(|v| v.as_slice()).unwrap_or(b"1"))
            .parse()
            .unwrap_or(1);
        let h = self.ensure_hash(&k);
        let cur: i64 = h
            .get(&field)
            .and_then(|v| String::from_utf8_lossy(v).parse().ok())
            .unwrap_or(0);
        let new_val = cur + delta;
        h.insert(field, new_val.to_string().into_bytes());
        Ok(Value::Int(new_val))
    }

    // -- set commands -------------------------------------------------------

    fn ensure_set(&mut self, k: &str) -> &mut HashSet<Vec<u8>> {
        self.data
            .entry(k.to_string())
            .or_insert_with(|| Stored::Set(HashSet::new()));
        match self.data.get_mut(k) {
            Some(Stored::Set(s)) => s,
            _ => unreachable!(),
        }
    }

    fn cmd_sadd(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        let s = self.ensure_set(&k);
        let mut count = 0i64;
        for member in &args[2..] {
            if s.insert(member.clone()) {
                count += 1;
            }
        }
        Ok(Value::Int(count))
    }

    fn cmd_smembers(&self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        match self.data.get(&k) {
            Some(Stored::Set(s)) => {
                let arr: Vec<Value> = s.iter().map(|v| Self::bulk(v)).collect();
                Ok(Value::Array(arr))
            }
            _ => Ok(Value::Array(vec![])),
        }
    }

    fn cmd_srem(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        let mut count = 0i64;
        if let Some(Stored::Set(s)) = self.data.get_mut(&k) {
            for member in &args[2..] {
                if s.remove(member.as_slice()) {
                    count += 1;
                }
            }
        }
        Ok(Value::Int(count))
    }

    // -- list commands ------------------------------------------------------

    fn ensure_list(&mut self, k: &str) -> &mut VecDeque<Vec<u8>> {
        self.data
            .entry(k.to_string())
            .or_insert_with(|| Stored::List(VecDeque::new()));
        match self.data.get_mut(k) {
            Some(Stored::List(l)) => l,
            _ => unreachable!(),
        }
    }

    fn cmd_rpush(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        let l = self.ensure_list(&k);
        for v in &args[2..] {
            l.push_back(v.clone());
        }
        Ok(Value::Int(l.len() as i64))
    }

    fn cmd_lpush(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        let l = self.ensure_list(&k);
        for v in &args[2..] {
            l.push_front(v.clone());
        }
        Ok(Value::Int(l.len() as i64))
    }

    fn cmd_rpop(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        match self.data.get_mut(&k) {
            Some(Stored::List(l)) => match l.pop_back() {
                Some(v) => Ok(Self::bulk(&v)),
                None => Ok(Value::Nil),
            },
            _ => Ok(Value::Nil),
        }
    }

    fn cmd_lpop(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        match self.data.get_mut(&k) {
            Some(Stored::List(l)) => match l.pop_front() {
                Some(v) => Ok(Self::bulk(&v)),
                None => Ok(Value::Nil),
            },
            _ => Ok(Value::Nil),
        }
    }

    fn cmd_lrange(&self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        let start: i64 = String::from_utf8_lossy(args.get(2).map(|v| v.as_slice()).unwrap_or(b"0"))
            .parse()
            .unwrap_or(0);
        let stop: i64 = String::from_utf8_lossy(args.get(3).map(|v| v.as_slice()).unwrap_or(b"-1"))
            .parse()
            .unwrap_or(-1);

        match self.data.get(&k) {
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
                    .map(|v| Self::bulk(v))
                    .collect();
                Ok(Value::Array(arr))
            }
            _ => Ok(Value::Array(vec![])),
        }
    }

    fn cmd_llen(&self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let k = Self::key(args, 1);
        match self.data.get(&k) {
            Some(Stored::List(l)) => Ok(Value::Int(l.len() as i64)),
            _ => Ok(Value::Int(0)),
        }
    }

    fn cmd_brpop(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        // Non-blocking in tests: try each key, return first non-empty list pop.
        // Last arg is timeout (ignored).
        let keys_end = args.len().saturating_sub(1); // skip timeout
        for a in &args[1..keys_end.max(1)] {
            let k = String::from_utf8_lossy(a).into_owned();
            if let Some(Stored::List(l)) = self.data.get_mut(&k) {
                if let Some(v) = l.pop_back() {
                    return Ok(Value::Array(vec![Self::bulk(a), Self::bulk(&v)]));
                }
            }
        }
        Ok(Value::Nil)
    }

    // -- scan ---------------------------------------------------------------

    fn cmd_scan(&self, args: &[Vec<u8>]) -> RedisResult<Value> {
        // SCAN cursor [MATCH pattern] [COUNT n]
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
                i += 2; // skip COUNT <n> or unknown pairs
            }
        }

        let keys: Vec<Value> = self
            .data
            .keys()
            .filter(|k| match &pattern {
                Some(p) => glob_match(p, k),
                None => true,
            })
            .map(|k| Value::BulkString(k.as_bytes().to_vec()))
            .collect();

        // Return cursor 0 (done) with all matching keys.
        Ok(Value::Array(vec![
            Value::BulkString(b"0".to_vec()),
            Value::Array(keys),
        ]))
    }
}

// ---------------------------------------------------------------------------
// ConnectionLike impl
// ---------------------------------------------------------------------------

impl ConnectionLike for MockRedisConnection {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> redis::RedisFuture<'a, Value> {
        let result = self.exec(cmd);
        Box::pin(std::future::ready(result))
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        _pipeline: &'a Pipeline,
        _offset: usize,
        _count: usize,
    ) -> redis::RedisFuture<'a, Vec<Value>> {
        // Pipeline execution not used by ares-core state functions.
        Box::pin(std::future::ready(Err(RedisError::from((
            ErrorKind::InvalidClientConfig,
            "pipeline not supported in mock",
        )))))
    }

    fn get_db(&self) -> i64 {
        0
    }
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
                    return false; // pattern doesn't start with *
                }
                pos += idx + part.len();
            }
            None => return false,
        }
    }
    // If pattern doesn't end with *, input must end exactly.
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
}
