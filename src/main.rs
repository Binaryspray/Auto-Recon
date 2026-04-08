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

use cli::{Cli, Commands, FilterType, OutputFormat};
use api::client::H1Client;
use db::cache::Cache;
use scorer::engine::score_program;
use scorer::weights::Weights;
use filter::mobility::is_mobility_target;
use filter::android::has_android;

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

            for p in &programs {
                let scopes = client.fetch_scopes(&p.attributes.handle).await?;
                cache.upsert_scopes(&p.attributes.handle, &scopes).await?;
            }

            println!("Done. Data cached at {}", db_path);
        }

        Commands::List { top, filter, format } => {
            let cache = Cache::new(&db_path).await?;
            let weights = Weights::from_config(&config_path);
            let programs = cache.get_all_programs().await?;

            let mut scored: Vec<_> = Vec::new();
            let mut mobility_flags: Vec<bool> = Vec::new();

            for p in &programs {
                let scopes = cache.get_scopes_for(&p.attributes.handle).await?;
                let is_mob = is_mobility_target(p, &scopes);
                let is_andr = has_android(&scopes);

                let dominated = filter.iter().any(|f| match f {
                    FilterType::Android => !is_andr,
                    FilterType::Mobility => !is_mob,
                });
                if dominated {
                    continue;
                }

                let score = score_program(p, &scopes, &weights);
                scored.push(score);
                mobility_flags.push(is_mob);
            }

            scored.sort_by(|a, b| b.total.partial_cmp(&a.total).unwrap());
            let mut indexed: Vec<_> = scored.iter().zip(mobility_flags.iter()).enumerate().collect();
            indexed.sort_by(|a, b| b.1.0.total.partial_cmp(&a.1.0.total).unwrap());
            let sorted_mobility: Vec<bool> = indexed.iter().map(|(_, (_, &m))| m).collect();
            let mobility_flags = sorted_mobility;

            let n = top.unwrap_or(scored.len());
            let scored = &scored[..n.min(scored.len())];
            let mobility_flags = &mobility_flags[..n.min(mobility_flags.len())];

            match format {
                OutputFormat::Table => {
                    println!("{}", output::table::render_table(scored, mobility_flags));
                }
                OutputFormat::Json => {
                    println!("{}", output::json::render_json(scored, mobility_flags));
                }
                OutputFormat::Csv => {
                    println!("{}", output::json::render_csv(scored, mobility_flags));
                }
            }
        }

        Commands::Export { format, output: out_path } => {
            let cache = Cache::new(&db_path).await?;
            let weights = Weights::from_config(&config_path);
            let programs = cache.get_all_programs().await?;

            let mut scored: Vec<_> = Vec::new();
            let mut mobility_flags: Vec<bool> = Vec::new();

            for p in &programs {
                let scopes = cache.get_scopes_for(&p.attributes.handle).await?;
                let is_mob = is_mobility_target(p, &scopes);
                let score = score_program(p, &scopes, &weights);
                scored.push(score);
                mobility_flags.push(is_mob);
            }

            scored.sort_by(|a, b| b.total.partial_cmp(&a.total).unwrap());

            let content = match format {
                OutputFormat::Json => output::json::render_json(&scored, &mobility_flags),
                OutputFormat::Csv => output::json::render_csv(&scored, &mobility_flags),
                OutputFormat::Table => output::table::render_table(&scored, &mobility_flags),
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
