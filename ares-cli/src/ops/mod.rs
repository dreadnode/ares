mod backfill;
#[cfg(feature = "blue")]
mod correlate;
mod delete;
#[cfg(feature = "blue")]
mod evaluate;
mod inject;
mod kill;
mod list;
mod loot;
mod queue;
mod report;
pub(crate) mod resolve;
mod runtime;
mod status;
mod stop;
pub(crate) mod submit;
mod tasks;

use anyhow::Result;

use crate::cli::OpsCommands;
use crate::detection::ops_export_detection;

pub(crate) async fn run_ops(cmd: OpsCommands, redis_url: Option<String>) -> Result<()> {
    match cmd {
        OpsCommands::List { latest } => list::ops_list(redis_url, latest).await,
        OpsCommands::Status {
            operation_id,
            latest,
        } => status::ops_status(redis_url, operation_id, latest).await,
        OpsCommands::Runtime {
            operation_id,
            latest,
        } => runtime::ops_runtime(redis_url, operation_id, latest).await,
        OpsCommands::Loot {
            operation_id,
            latest,
            json,
            watch,
            diff,
        } => loot::ops_loot(redis_url, operation_id, latest, json, watch, diff).await,
        OpsCommands::Tasks {
            operation_id,
            latest,
            status,
            role,
        } => tasks::ops_tasks(redis_url, operation_id, latest, status, role).await,
        OpsCommands::Queue => queue::ops_queue(redis_url).await,
        OpsCommands::ClaimNext { timeout } => queue::ops_claim_next(redis_url, timeout).await,
        OpsCommands::InjectCredential {
            operation_id,
            username,
            password,
            domain,
            source,
            is_admin,
        } => {
            inject::ops_inject_credential(
                redis_url,
                operation_id,
                username,
                password,
                domain,
                source,
                is_admin,
            )
            .await
        }
        OpsCommands::InjectVulnerability {
            operation_id,
            vuln_type,
            target_ip,
            target_hostname,
            target_spn,
            account_name,
            domain,
            details,
        } => {
            inject::ops_inject_vulnerability(
                redis_url,
                operation_id,
                vuln_type,
                target_ip,
                target_hostname,
                target_spn,
                account_name,
                domain,
                details,
            )
            .await
        }
        OpsCommands::InjectHost {
            operation_id,
            ip,
            hostname,
        } => inject::ops_inject_host(redis_url, operation_id, ip, hostname).await,
        OpsCommands::Stop {
            operation_id,
            latest,
        } => stop::ops_stop(redis_url, operation_id, latest).await,
        OpsCommands::Delete {
            operation_id,
            force,
        } => delete::ops_delete(redis_url, operation_id, force).await,
        OpsCommands::Kill { operation_id, all } => {
            kill::ops_kill(redis_url, operation_id, all).await
        }
        OpsCommands::InjectHash {
            operation_id,
            username,
            hash_value,
            domain,
            hash_type,
            source,
            aes_key,
        } => {
            inject::ops_inject_hash(
                redis_url,
                operation_id,
                username,
                hash_value,
                domain,
                hash_type,
                source,
                aes_key,
            )
            .await
        }
        OpsCommands::InjectDomainSid {
            operation_id,
            domain,
            sid,
        } => inject::ops_inject_domain_sid(redis_url, operation_id, domain, sid).await,
        OpsCommands::BackfillDomains { operation_id } => {
            backfill::ops_backfill_domains(redis_url, operation_id).await
        }
        OpsCommands::OffloadCost {
            operation_id,
            latest,
        } => backfill::ops_offload_cost(redis_url, operation_id, latest).await,
        OpsCommands::Report {
            operation_id,
            latest,
            regenerate,
            output_dir,
        } => report::ops_report(redis_url, operation_id, latest, regenerate, output_dir).await,
        OpsCommands::ExportDetection {
            operation_id,
            latest,
            output_dir,
            json,
            no_markdown,
        } => {
            ops_export_detection(
                redis_url,
                operation_id,
                latest,
                output_dir,
                json,
                !no_markdown,
            )
            .await
        }
        OpsCommands::Cleanup { max_age_hours } => {
            delete::ops_cleanup(redis_url, max_age_hours).await
        }
        #[cfg(feature = "blue")]
        OpsCommands::Correlate {
            reports_dir,
            time_window,
            json,
        } => correlate::ops_correlate(reports_dir, time_window, json),
        #[cfg(feature = "blue")]
        OpsCommands::Evaluate {
            states_dir,
            state_file,
            output_dir,
            json,
            save,
        } => evaluate::ops_evaluate(states_dir, state_file, output_dir, json, save),
        OpsCommands::Submit {
            target,
            domain,
            mut ips,
            operation_id,
            username,
            password,
            ntlm_hash,
            resume,
            model,
            max_steps,
            env,
            resolve_targets,
            aws_profile,
            aws_region,
            pin_active,
            follow,
            follow_interval,
            auto_report,
            report_dir,
        } => {
            // Resolve targets from EC2 if requested and no IPs provided
            if ips.is_empty() {
                if resolve_targets || !resolve::looks_like_ip(&target) {
                    ips = resolve::resolve_ec2_targets(&target, &aws_profile, &aws_region)?;
                } else {
                    // Target itself looks like IPs (e.g., "192.168.58.10,192.168.58.11")
                    ips = target.split(',').map(|s| s.trim().to_string()).collect();
                }
            }
            let op_id = submit::ops_submit(
                redis_url.clone(),
                target,
                domain,
                ips,
                operation_id,
                username,
                password,
                ntlm_hash,
                resume,
                model,
                max_steps,
                env,
                pin_active,
            )
            .await?;
            if follow {
                submit::follow_operation(redis_url.clone(), &op_id, follow_interval).await?;
            }
            if auto_report {
                report::ops_report(redis_url, Some(op_id), false, false, report_dir).await?;
            }
            Ok(())
        }
    }
}
