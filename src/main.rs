pub mod api;
pub mod db;
pub mod filter;
pub mod scorer;
pub mod output;
pub mod cli;
pub mod select;
pub mod recon;
pub mod review;
pub mod llm;

use anyhow::Result;
use clap::Parser;
use dotenvy::dotenv;

use cli::{Cli, Commands, OutputFormat};
use api::client::H1Client;
use db::cache::Cache;
use scorer::engine::score_program;
use scorer::weights::Weights;

fn get_db_path() -> String {
    let home = dirs::home_dir().unwrap_or_else(|| ".".into());
    let dir = home.join(".h1scout");
    std::fs::create_dir_all(&dir).ok();
    dir.join("h1scout.db").to_string_lossy().to_string()
}

fn get_config_path() -> String {
    let home = dirs::home_dir().unwrap_or_else(|| ".".into());
    home.join(".h1scout").join("config.toml").to_string_lossy().to_string()
}

fn get_projects_dir(override_dir: Option<&str>) -> String {
    if let Some(d) = override_dir {
        return d.to_string();
    }
    let home = dirs::home_dir().unwrap_or_else(|| ".".into());
    let dir = home.join(".h1scout").join("projects");
    std::fs::create_dir_all(&dir).ok();
    dir.to_string_lossy().to_string()
}

/// Fetch all programs and scopes from H1 API, store in cache.
/// Used by both Fetch command and auto-fetch logic.
async fn do_fetch(cache: &Cache, db_path: &str) -> Result<()> {
    let username = std::env::var("H1_USERNAME")
        .map_err(|_| anyhow::anyhow!("H1_USERNAME env var required"))?;
    let api_token = std::env::var("H1_API_TOKEN")
        .map_err(|_| anyhow::anyhow!("H1_API_TOKEN env var required"))?;

    let client = H1Client::new(&username, &api_token);

    println!("Fetching programs from H1 API...");
    let programs = client.fetch_all_programs().await?;
    println!("Fetched {} programs.", programs.len());

    cache.upsert_programs(&programs).await?;

    let pb = indicatif::ProgressBar::new(programs.len() as u64);
    pb.set_style(indicatif::ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40} {pos}/{len} scopes fetched")
        .unwrap());

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(5));
    let client = std::sync::Arc::new(client);
    let mut pending: Vec<String> = programs.iter().map(|p| p.attributes.handle.clone()).collect();
    let total = pending.len();
    let mut done = 0usize;
    let mut round = 1;
    let max_rounds = 5;

    while !pending.is_empty() && round <= max_rounds {
        if round > 1 {
            println!("Round {} — retrying {} failed scopes (waiting 10s)...", round, pending.len());
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }

        let mut handles = Vec::new();
        for handle in &pending {
            let sem = semaphore.clone();
            let client = client.clone();
            let handle = handle.clone();
            let h = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let scopes = client.fetch_scopes(&handle).await;
                (handle, scopes)
            });
            handles.push(h);
        }

        let mut failed = Vec::new();
        for h in handles {
            let (handle, scopes_result) = h.await?;
            match scopes_result {
                Ok(scopes) => {
                    cache.upsert_scopes(&handle, &scopes).await?;
                    done += 1;
                }
                Err(_) => failed.push(handle),
            }
            pb.inc(1);
        }
        pending = failed;
        round += 1;
    }
    pb.finish_and_clear();

    if !pending.is_empty() {
        eprintln!("Warning: {} scopes could not be fetched after {} rounds", pending.len(), max_rounds);
    }
    println!("Done. {}/{} scopes cached at {}", done, total, db_path);
    Ok(())
}

/// Auto-fetch if cache is empty. Used by list/select.
async fn ensure_cache_populated(cache: &Cache, db_path: &str) -> Result<()> {
    let programs = cache.get_all_programs().await?;
    if programs.is_empty() {
        println!("Cache is empty. Auto-fetching from H1 API...");
        do_fetch(cache, db_path).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let cli = Cli::parse();
    let db_path = get_db_path();
    let config_path = get_config_path();

    match cli.command {
        Commands::Fetch { force, dry_run } => {
            let cache = Cache::new(&db_path).await?;

            if !force && !cache.is_stale(86400).await {
                println!("Cache is fresh (< 24h). Use --force to refresh.");
                return Ok(());
            }

            if dry_run {
                println!("Would fetch programs from HackerOne API.");
                return Ok(());
            }

            do_fetch(&cache, &db_path).await?;
        }

        Commands::List { top, min_scopes, format } => {
            let cache = Cache::new(&db_path).await?;
            ensure_cache_populated(&cache, &db_path).await?;
            let weights = Weights::from_config(&config_path);
            let programs = cache.get_all_programs().await?;
            let min = min_scopes.unwrap_or(1);

            let mut scored: Vec<_> = Vec::new();

            for p in &programs {
                let scopes = cache.get_scopes_for(&p.attributes.handle).await?;
                let score = score_program(p, &scopes, &weights);

                if score.web_scope_count < min {
                    continue;
                }

                scored.push(score);
            }

            scored.sort_by(|a, b| b.total.partial_cmp(&a.total).unwrap());

            let n = top.unwrap_or(scored.len());
            let scored = &scored[..n.min(scored.len())];

            match format {
                OutputFormat::Table => {
                    println!("{}", output::table::render_table(scored));
                }
                OutputFormat::Json => {
                    println!("{}", output::json::render_json(scored));
                }
                OutputFormat::Csv => {
                    println!("{}", output::json::render_csv(scored));
                }
            }
        }

        Commands::Export { format, output: out_path } => {
            let cache = Cache::new(&db_path).await?;
            ensure_cache_populated(&cache, &db_path).await?;
            let weights = Weights::from_config(&config_path);
            let programs = cache.get_all_programs().await?;

            let mut scored: Vec<_> = Vec::new();

            for p in &programs {
                let scopes = cache.get_scopes_for(&p.attributes.handle).await?;
                let score = score_program(p, &scopes, &weights);
                if score.web_scope_count == 0 {
                    continue;
                }
                scored.push(score);
            }

            scored.sort_by(|a, b| b.total.partial_cmp(&a.total).unwrap());

            let content = match format {
                OutputFormat::Json => output::json::render_json(&scored),
                OutputFormat::Csv => output::json::render_csv(&scored),
                OutputFormat::Table => output::table::render_table(&scored),
            };

            match out_path {
                Some(path) => {
                    std::fs::write(&path, &content)?;
                    println!("Exported to {}", path);
                }
                None => println!("{}", content),
            }
        }

        Commands::Select { projects_dir, skip_nuclei, skill, no_review } => {
            let projects_dir = get_projects_dir(projects_dir.as_deref());
            let cache = Cache::new(&db_path).await?;
            ensure_cache_populated(&cache, &db_path).await?;
            let weights = Weights::from_config(&config_path);

            let opts = recon::ReconOptions {
                skip_nuclei: skip_nuclei || std::env::var("SKIP_NUCLEI").is_ok(),
                skill,
            };

            select::run_select(&cache, &weights, &projects_dir, opts, !no_review).await?;
        }

        Commands::Recon { project_id, only_ap, skip_nuclei, skill } => {
            let projects_dir = get_projects_dir(None);
            let project_dir = std::path::Path::new(&projects_dir).join(&project_id);

            let opts = recon::ReconOptions {
                skip_nuclei: skip_nuclei || std::env::var("SKIP_NUCLEI").is_ok(),
                skill,
            };

            if only_ap {
                recon::run_recon_ap_only(&project_dir, opts).await?;
            } else {
                recon::run_recon(&project_dir, opts).await?;
            }
        }

        Commands::Projects { latest } => {
            let projects_dir = get_projects_dir(None);
            let projects = review::find_completed_projects(std::path::Path::new(&projects_dir))?;

            if projects.is_empty() {
                println!("No completed projects found at {}", projects_dir);
                return Ok(());
            }

            let to_show = if latest { &projects[..1] } else { &projects[..] };

            println!("{:30}  {:>6}  {:>5}  Created", "Project", "Score", "APs");
            println!("{}", "─".repeat(70));
            for (name, rr) in to_show {
                println!(
                    "{:30}  {:>6.1}  {:>5}  {}",
                    name,
                    rr.bbp.score,
                    rr.attack_points.len(),
                    &rr.created_at[..rr.created_at.len().min(19)],
                );
            }
        }

        Commands::Review { project_id } => {
            let projects_dir = get_projects_dir(None);
            review::run_review(&projects_dir, project_id.as_deref()).await?;
        }
    }

    Ok(())
}
