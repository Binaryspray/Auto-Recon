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

#[tokio::main]
async fn main() -> Result<()> {
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

            let username = std::env::var("H1_USERNAME")
                .expect("H1_USERNAME env var required");
            let api_token = std::env::var("H1_API_TOKEN")
                .expect("H1_API_TOKEN env var required");

            let client = H1Client::new(&username, &api_token);

            println!("Fetching programs...");
            let programs = client.fetch_all_programs().await?;
            println!("Fetched {} programs.", programs.len());

            cache.upsert_programs(&programs).await?;

            // Concurrent scope fetching (10 at a time)
            let pb = indicatif::ProgressBar::new(programs.len() as u64);
            pb.set_style(indicatif::ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40} {pos}/{len} scopes fetched")
                .unwrap());

            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(10));
            let client = std::sync::Arc::new(client);
            let mut handles = Vec::new();

            for p in &programs {
                let sem = semaphore.clone();
                let client = client.clone();
                let handle = p.attributes.handle.clone();

                let h = tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let scopes = client.fetch_scopes(&handle).await;
                    (handle, scopes)
                });
                handles.push(h);
            }

            for h in handles {
                let (handle, scopes_result) = h.await?;
                match scopes_result {
                    Ok(scopes) => cache.upsert_scopes(&handle, &scopes).await?,
                    Err(e) => eprintln!("Warning: failed to fetch scopes for {}: {}", handle, e),
                }
                pb.inc(1);
            }

            pb.finish_and_clear();
            println!("Done. Data cached at {}", db_path);
        }

        Commands::List { top, min_scopes, format } => {
            let cache = Cache::new(&db_path).await?;
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

        Commands::Select { projects_dir } => {
            let projects_dir = get_projects_dir(projects_dir.as_deref());
            let cache = Cache::new(&db_path).await?;
            let weights = Weights::from_config(&config_path);

            select::run_select(&cache, &weights, &projects_dir).await?;
        }

        Commands::Review { project_id } => {
            let projects_dir = get_projects_dir(None);
            review::run_review(&projects_dir, project_id.as_deref()).await?;
        }
    }

    Ok(())
}
