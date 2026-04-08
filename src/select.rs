use anyhow::Result;
use chrono::Local;
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::api::models::{ScopeData, ProgramData};
use crate::db::cache::Cache;
use crate::scorer::engine::{score_program, ProgramScore};
use crate::scorer::weights::Weights;
use crate::filter::mobility::is_mobility_target;
use crate::filter::android::has_android;

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
        "has_android": score.has_android,
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

pub async fn run_select(cache: &Cache, weights: &Weights, projects_dir: &str) -> Result<()> {
    let programs = cache.get_all_programs().await?;

    // Score and sort
    let mut entries: Vec<(ProgramData, Vec<ScopeData>, ProgramScore, bool)> = Vec::new();
    for p in &programs {
        let scopes = cache.get_scopes_for(&p.attributes.handle).await?;
        let is_mob = is_mobility_target(p, &scopes);
        let score = score_program(p, &scopes, weights);
        entries.push((p.clone(), scopes, score, is_mob));
    }
    entries.sort_by(|a, b| b.2.total.partial_cmp(&a.2.total).unwrap());

    if entries.is_empty() {
        println!("No programs in cache. Run `h1scout fetch` first.");
        return Ok(());
    }

    // Build display items
    let items: Vec<String> = entries
        .iter()
        .map(|(p, scopes, score, _)| {
            let web_count = filter_web_scopes(scopes).len();
            let android = if has_android(scopes) { " [AND]" } else { "" };
            format!(
                "[{:.1}] {} ({}){} — web:{}",
                score.total, p.attributes.name, p.attributes.handle, android, web_count
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

    for idx in selections {
        let (program, scopes, score, _) = &entries[idx];
        let web_scopes = filter_web_scopes(scopes);

        if web_scopes.is_empty() {
            println!("Skipping {} — no web scopes.", program.attributes.handle);
            continue;
        }

        let project_id = make_project_id(&program.attributes.handle);
        let project_dir = init_project_dir(&project_id, base_dir, program, score, &web_scopes)?;
        println!("Created project: {}", project_dir.display());

        // Run recon pipeline
        crate::recon::run_recon(&project_dir).await?;
    }

    Ok(())
}
