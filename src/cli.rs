use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "h1scout", about = "HackerOne bug bounty program selector")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Fetch programs and scopes from HackerOne API
    Fetch {
        /// Force refresh even if cache is fresh
        #[arg(long)]
        force: bool,
        /// Print what would be fetched without actually fetching
        #[arg(long)]
        dry_run: bool,
    },
    /// List and rank programs by web recon score
    List {
        /// Show only top N results
        #[arg(long)]
        top: Option<usize>,
        /// Minimum web scope count to show
        #[arg(long)]
        min_scopes: Option<usize>,
        /// Output format
        #[arg(long, value_enum, default_value = "table")]
        format: OutputFormat,
    },
    /// Export results to a file
    Export {
        /// Output format
        #[arg(long, value_enum, default_value = "json")]
        format: OutputFormat,
        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },
    /// TUI: select BBPs and run Auto-Recon pipeline
    Select {
        /// Projects directory (default: ~/.h1scout/projects)
        #[arg(long)]
        projects_dir: Option<String>,
        /// Skip nuclei scan (recommended when behind WAF)
        #[arg(long)]
        skip_nuclei: bool,
        /// AP identification skill: "boundary" (default) or "vuln" (legacy)
        #[arg(long, default_value = "boundary")]
        skill: String,
        /// Don't auto-launch review TUI after recon completes
        #[arg(long)]
        no_review: bool,
    },
    /// Re-run recon on an existing project
    Recon {
        /// Project ID (e.g. varonis_20260409)
        #[arg(long)]
        project_id: String,
        /// Only re-run LLM AP identification (skip BBOT/httpx/gau/nuclei)
        #[arg(long)]
        only_ap: bool,
        /// Skip nuclei scan
        #[arg(long)]
        skip_nuclei: bool,
        /// AP identification skill: "boundary" (default) or "vuln" (legacy)
        #[arg(long, default_value = "boundary")]
        skill: String,
    },
    /// List completed projects
    Projects {
        /// Show only the most recent project
        #[arg(long)]
        latest: bool,
    },
    /// TUI: review attack points and generate Auto-Solve input
    Review {
        /// Specific project_id (if omitted, pick from list)
        #[arg(long)]
        project_id: Option<String>,
    },
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
}
