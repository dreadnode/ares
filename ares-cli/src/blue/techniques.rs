use std::collections::{HashMap, HashSet};

use anyhow::Result;
use redis::AsyncCommands;

use crate::redis_conn::connect_redis;

use super::resolve_investigation_id;

pub(crate) async fn blue_techniques(
    redis_url: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let inv_id = resolve_investigation_id(&mut conn, investigation_id, latest).await?;

    let techniques_key = format!("ares:blue:inv:{inv_id}:techniques");
    let techniques: HashSet<String> = conn.smembers(&techniques_key).await?;

    let names_key = format!("ares:blue:inv:{inv_id}:technique_names");
    let names: HashMap<String, String> = conn.hgetall(&names_key).await?;

    if techniques.is_empty() {
        println!("No techniques identified for investigation: {inv_id}");
        return Ok(());
    }

    println!("MITRE ATT&CK Techniques for investigation: {inv_id}");
    println!("{}", "-".repeat(60));

    let mut sorted_techniques: Vec<String> = techniques.into_iter().collect();
    sorted_techniques.sort();

    for tech_id in &sorted_techniques {
        if let Some(name) = names.get(tech_id) {
            if !name.is_empty() {
                println!("  {tech_id}: {name}");
            } else {
                println!("  {tech_id}");
            }
        } else {
            println!("  {tech_id}");
        }
    }

    Ok(())
}
