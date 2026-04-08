use serde::Serialize;
use crate::scorer::engine::ProgramScore;

#[derive(Serialize)]
struct JsonEntry {
    handle: String,
    name: String,
    total_score: f64,
    bounty_score: f64,
    web_scope_score: f64,
    health_score: f64,
    response_score: f64,
    difficulty_score: f64,
    web_scope_count: usize,
}

pub fn render_json(scores: &[ProgramScore]) -> String {
    let entries: Vec<JsonEntry> = scores
        .iter()
        .map(|s| JsonEntry {
            handle: s.handle.clone(),
            name: s.name.clone(),
            total_score: s.total,
            bounty_score: s.bounty_score,
            web_scope_score: s.web_scope_score,
            health_score: s.health_score,
            response_score: s.response_score,
            difficulty_score: s.difficulty_score,
            web_scope_count: s.web_scope_count,
        })
        .collect();

    serde_json::to_string_pretty(&entries).unwrap()
}

pub fn render_csv(scores: &[ProgramScore]) -> String {
    let mut lines = vec!["handle,name,total,bounty,web_scope,health,response,difficulty,web_scopes".to_string()];
    for s in scores {
        lines.push(format!(
            "{},{},{:.1},{:.0},{:.0},{:.0},{:.0},{:.0},{}",
            s.handle, s.name, s.total, s.bounty_score, s.web_scope_score,
            s.health_score, s.response_score, s.difficulty_score, s.web_scope_count
        ));
    }
    lines.join("\n")
}
