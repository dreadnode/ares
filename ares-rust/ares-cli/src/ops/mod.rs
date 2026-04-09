mod backfill;
mod correlate;
mod delete;
mod evaluate;
mod inject;
mod list;
mod loot;
mod queue;
mod report;
mod runtime;
mod status;
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
        OpsCommands::Delete {
            operation_id,
            force,
        } => delete::ops_delete(redis_url, operation_id, force).await,
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
        OpsCommands::Correlate {
            reports_dir,
            time_window,
            json,
        } => correlate::ops_correlate(reports_dir, time_window, json),
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
            ips,
            operation_id,
            username,
            password,
            ntlm_hash,
            resume,
            model,
            max_steps,
            env,
        } => {
            submit::ops_submit(
                redis_url,
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
            )
            .await
        }
    }
}
