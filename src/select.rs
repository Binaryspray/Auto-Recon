use anyhow::Result;
use chrono::Local;
use indicatif::MultiProgress;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::api::models::{ScopeData, ProgramData};
use crate::db::cache::Cache;
use crate::scorer::engine::{score_program, ProgramScore};
use crate::scorer::weights::Weights;

const OUT_OF_SCOPE_KEYWORDS: &[&str] = &[
    "out of scope",
    "do not test",
    "no automated",
    "no scanning",
    "excluded",
];

#[derive(Debug, Clone, Serialize)]
pub struct WebScope {
    pub identifier: String,
    pub asset_type: String,
    pub max_severity: Option<String>,
    pub instruction: Option<String>,
}

pub fn make_project_id(handle: &str) -> String {
    let date = Local::now().format("%Y%m%d");
    format!("{}_{}", handle, date)
}

pub fn split_identifiers(identifier: &str) -> Vec<String> {
    identifier
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn filter_web_scopes(scopes: &[ScopeData]) -> Vec<WebScope> {
    let mut result = Vec::new();

    for scope in scopes {
        let attrs = &scope.attributes;

        // Web types only
        if attrs.asset_type != "WILDCARD" && attrs.asset_type != "URL" {
            continue;
        }

        // Must be eligible
        if !attrs.eligible_for_bounty || !attrs.eligible_for_submission {
            continue;
        }

        // Check instruction for out-of-scope keywords
        if let Some(ref instruction) = attrs.instruction {
            let lower = instruction.to_lowercase();
            if OUT_OF_SCOPE_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
                continue;
            }
        }

        // Split multi-identifiers
        let identifiers = split_identifiers(&attrs.asset_identifier);
        for id in identifiers {
            result.push(WebScope {
                identifier: id,
                asset_type: attrs.asset_type.clone(),
                max_severity: attrs.max_severity.clone(),
                instruction: attrs.instruction.clone(),
            });
        }
    }

    result
}

pub fn init_project_dir(project_id: &str, base_dir: &Path, program: &ProgramData, score: &ProgramScore, web_scopes: &[WebScope]) -> Result<PathBuf> {
    let project_dir = base_dir.join(project_id);
    let recon_dir = project_dir.join("recon");
    std::fs::create_dir_all(&recon_dir)?;

    // program_info.json
    let info = serde_json::json!({
        "handle": program.attributes.handle,
        "name": program.attributes.name,
        "score": score.total,
        "web_scopes": score.web_scope_count,
        "difficulty": score.difficulty_score,
    });
    std::fs::write(
        project_dir.join("program_info.json"),
        serde_json::to_string_pretty(&info)?,
    )?;

    // rule.csv
    let mut csv = String::from("identifier,asset_type,max_severity,instruction\n");
    for ws in web_scopes {
        csv.push_str(&format!(
            "{},{},{},{}\n",
            ws.identifier,
            ws.asset_type,
            ws.max_severity.as_deref().unwrap_or(""),
            ws.instruction.as_deref().unwrap_or(""),
        ));
    }
    std::fs::write(project_dir.join("rule.csv"), csv)?;

    Ok(project_dir)
}

pub async fn run_select(cache: &Cache, weights: &Weights, projects_dir: &str, force: bool, skip: Vec<String>) -> Result<()> {
    let skip_steps: HashSet<String> = skip.into_iter().collect();
    let programs = cache.get_all_programs().await?;

    // Score and sort — skip programs with no web scopes
    let mut entries: Vec<(ProgramData, Vec<ScopeData>, ProgramScore)> = Vec::new();
    for p in &programs {
        let scopes = cache.get_scopes_for(&p.attributes.handle).await?;
        let score = score_program(p, &scopes, weights);
        if score.web_scope_count == 0 {
            continue;
        }
        entries.push((p.clone(), scopes, score));
    }
    entries.sort_by(|a, b| b.2.total.partial_cmp(&a.2.total).unwrap());

    if entries.is_empty() {
        println!("No programs with web scopes in cache. Run `h1scout fetch` first.");
        return Ok(());
    }

    // Build display items
    let items: Vec<String> = entries
        .iter()
        .map(|(p, _, score)| {
            format!(
                "[{:.1}] {} ({}) — web:{} diff:{:.0}",
                score.total, p.attributes.name, p.attributes.handle,
                score.web_scope_count, score.difficulty_score
            )
        })
        .collect();

    // TUI multi-select
    let selections = dialoguer::MultiSelect::new()
        .with_prompt("Select BBPs to recon (Space to toggle, Enter to confirm)")
        .items(&items)
        .interact()?;

    if selections.is_empty() {
        println!("No programs selected.");
        return Ok(());
    }

    let base_dir = Path::new(projects_dir);

    // Prepare selected BBPs
    let mut bbp_tasks = Vec::new();
    for idx in selections {
        let (program, scopes, score) = &entries[idx];
        let web_scopes = filter_web_scopes(scopes);

        if web_scopes.is_empty() {
            println!("Skipping {} — no web scopes.", program.attributes.handle);
            continue;
        }

        let project_id = make_project_id(&program.attributes.handle);
        let project_dir = init_project_dir(&project_id, base_dir, program, score, &web_scopes)?;

        // Save program policy if available
        if let Ok(Some(policy)) = cache.get_policy(&program.attributes.handle).await {
            let _ = std::fs::write(project_dir.join("policy.md"), &policy);
        }

        bbp_tasks.push((program.attributes.handle.clone(), project_dir));
    }

    if bbp_tasks.len() == 1 {
        // Single BBP — run directly without MultiProgress overhead
        let (handle, project_dir) = &bbp_tasks[0];
        println!("Starting recon: {}", handle);
        crate::recon::run_recon(project_dir, force, &skip_steps).await?;
    } else {
        // Multiple BBPs — run in parallel with semaphore
        let mp = MultiProgress::new();
        let sem = Arc::new(Semaphore::new(3));
        let skip_steps = Arc::new(skip_steps);

        let mut handles = Vec::new();
        for (handle, project_dir) in bbp_tasks {
            let sem = sem.clone();
            let skip_steps = skip_steps.clone();
            let mp_clone = mp.clone();

            let h = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let _ = mp_clone; // keep MultiProgress alive
                println!("Starting recon: {}", handle);
                match crate::recon::run_recon(&project_dir, force, &skip_steps).await {
                    Ok(()) => println!("Completed: {}", handle),
                    Err(e) => eprintln!("Failed {}: {}", handle, e),
                }
            });
            handles.push(h);
        }

        // Wait for all BBPs
        for h in handles {
            let _ = h.await;
        }
    }

    Ok(())
}
