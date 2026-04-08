use anyhow::{anyhow, Result};
use std::path::Path;

use crate::recon::{AttackPoint, ReconResult};

pub fn format_ap_display(ap: &AttackPoint) -> String {
    let reasoning = if ap.evidence.llm_reasoning.is_some() {
        " (LLM)"
    } else {
        ""
    };
    format!(
        "[{}] {:20} — {}{}",
        ap.priority, ap.category, ap.url, reasoning
    )
}

pub fn generate_solve_input(rr: &ReconResult, selected_indices: &[usize]) -> String {
    let selected_aps: Vec<&AttackPoint> = selected_indices
        .iter()
        .filter_map(|&i| rr.attack_points.get(i))
        .collect();

    let output = serde_json::json!({
        "project_id": rr.project_id,
        "bbp": rr.bbp,
        "target": rr.target,
        "scope": rr.scope,
        "selected_attack_points": selected_aps,
    });

    serde_json::to_string_pretty(&output).unwrap()
}

fn load_rr(project_dir: &Path) -> Result<ReconResult> {
    let rr_path = project_dir.join("RR.json");
    if !rr_path.exists() {
        return Err(anyhow!("RR.json not found in {}", project_dir.display()));
    }
    let content = std::fs::read_to_string(&rr_path)?;
    let rr: ReconResult = serde_json::from_str(&content)?;
    Ok(rr)
}

fn find_completed_projects(projects_dir: &Path) -> Result<Vec<(String, ReconResult)>> {
    let mut results = Vec::new();

    if !projects_dir.exists() {
        return Ok(results);
    }

    for entry in std::fs::read_dir(projects_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Ok(rr) = load_rr(&path) {
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                results.push((name, rr));
            }
        }
    }

    results.sort_by(|a, b| b.1.bbp.score.partial_cmp(&a.1.bbp.score).unwrap_or(std::cmp::Ordering::Equal));
    Ok(results)
}

pub async fn run_review(projects_dir: &str, project_id: Option<&str>) -> Result<()> {
    let base = Path::new(projects_dir);

    let rr = if let Some(pid) = project_id {
        load_rr(&base.join(pid))?
    } else {
        // List projects and let user pick
        let projects = find_completed_projects(base)?;
        if projects.is_empty() {
            println!("No completed projects with RR.json found.");
            return Ok(());
        }

        let items: Vec<String> = projects
            .iter()
            .map(|(name, rr)| {
                format!(
                    "[{:.1}] {} — {} APs",
                    rr.bbp.score, name, rr.attack_points.len()
                )
            })
            .collect();

        let selection = dialoguer::Select::new()
            .with_prompt("Select project to review")
            .items(&items)
            .interact()?;

        projects[selection].1.clone()
    };

    if rr.attack_points.is_empty() {
        println!("No attack points found in this project.");
        return Ok(());
    }

    // Display APs
    let ap_items: Vec<String> = rr.attack_points.iter().map(format_ap_display).collect();

    let selections = dialoguer::MultiSelect::new()
        .with_prompt("Select APs to send to Auto-Solve (Space to toggle, Enter to confirm)")
        .items(&ap_items)
        .interact()?;

    if selections.is_empty() {
        println!("No APs selected.");
        return Ok(());
    }

    let output = generate_solve_input(&rr, &selections);
    println!("{}", output);

    Ok(())
}
