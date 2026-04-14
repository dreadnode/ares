use std::path::Path;

use anyhow::{Context, Result};
use tracing::error;

use ares_core::eval::workflow::{
    evaluate_dataset, evaluate_scenario, save_evaluation_result, save_gap_analysis,
    EvaluationDataset, EvaluationScenario,
};

pub(crate) fn ops_evaluate(
    states_dir: Option<String>,
    state_file: Option<String>,
    output_dir: String,
    json_output: bool,
    save: bool,
) -> Result<()> {
    if states_dir.is_none() && state_file.is_none() {
        anyhow::bail!("Specify either --states-dir or --state-file");
    }

    let output_path = Path::new(&output_dir);

    if let Some(ref dir) = states_dir {
        // Dataset mode: evaluate all state files in directory
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            anyhow::bail!("States directory does not exist: {dir}");
        }

        let dataset = EvaluationDataset::from_directory(dir_path, None)
            .context("Failed to load evaluation dataset")?;

        if dataset.scenarios.is_empty() {
            println!("No JSON state files found in {dir}");
            return Ok(());
        }

        println!(
            "Evaluating {} scenarios from {}",
            dataset.scenarios.len(),
            dir
        );

        // Evaluate each scenario with detailed output
        for scenario in &dataset.scenarios {
            match evaluate_scenario(scenario) {
                Ok(output) => {
                    if json_output {
                        let json = serde_json::to_string_pretty(&output.result.to_value())?;
                        println!("{json}");
                    } else {
                        println!("\n--- {} ---", output.scenario_name);
                        println!("{}", output.result.to_summary());
                        println!("\nGap Analysis:");
                        println!("{}", output.gap_analysis.to_markdown());
                    }

                    if save {
                        let eval_path = save_evaluation_result(&output.result, output_path)?;
                        let gap_path = save_gap_analysis(&output.gap_analysis, output_path)?;
                        if !json_output {
                            println!("Saved: {}", eval_path.display());
                            println!("Saved: {}", gap_path.display());
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to evaluate {}: {e:#}", scenario.name);
                }
            }
        }

        // Print aggregate summary
        let dataset_result =
            evaluate_dataset(&dataset).context("Failed to aggregate dataset results")?;

        if json_output {
            let json = serde_json::to_string_pretty(&dataset_result.to_value())?;
            println!("{json}");
        } else {
            println!("\n=== Dataset Summary ===");
            println!("{}", dataset_result.to_summary());
        }
    } else if let Some(ref file) = state_file {
        // Single file mode
        let path = Path::new(file);
        if !path.exists() {
            anyhow::bail!("State file does not exist: {file}");
        }

        let scenario = EvaluationScenario {
            state_file: path.to_path_buf(),
            name: path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string(),
            tags: Vec::new(),
            ground_truth: None,
        };

        let output =
            evaluate_scenario(&scenario).with_context(|| format!("Failed to evaluate {file}"))?;

        if json_output {
            let json = serde_json::to_string_pretty(&output.result.to_value())?;
            println!("{json}");
        } else {
            println!("{}", output.result.to_summary());
            println!();
            println!("{}", output.gap_analysis.to_markdown());
        }

        if save {
            let eval_path = save_evaluation_result(&output.result, output_path)?;
            let gap_path = save_gap_analysis(&output.gap_analysis, output_path)?;
            if !json_output {
                println!("Saved: {}", eval_path.display());
                println!("Saved: {}", gap_path.display());
            }
        }
    }

    Ok(())
}
