use anyhow::Result;
use crate::db::cache::Cache;
use crate::scorer::weights::Weights;

pub async fn run_select(_cache: &Cache, _weights: &Weights, _projects_dir: &str) -> Result<()> {
    todo!("Step 4-1: select TUI")
}
