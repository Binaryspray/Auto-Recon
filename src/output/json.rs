use serde::Serialize;
use crate::scorer::engine::ProgramScore;

#[derive(Serialize)]
struct JsonEntry {
    handle: String,
    name: String,
    total_score: f64,
    bounty_score: f64,
    response_score: f64,
    scope_score: f64,
    health_score: f64,
    has_android: bool,
    is_mobility: bool,
}

pub fn render_json(scores: &[ProgramScore], mobility_flags: &[bool]) -> String {
    let entries: Vec<JsonEntry> = scores
        .iter()
        .zip(mobility_flags.iter())
        .map(|(s, &is_mobility)| JsonEntry {
            handle: s.handle.clone(),
            name: s.name.clone(),
            total_score: s.total,
            bounty_score: s.bounty_score,
            response_score: s.response_score,
            scope_score: s.scope_score,
            health_score: s.health_score,
            has_android: s.has_android,
            is_mobility,
        })
        .collect();

    serde_json::to_string_pretty(&entries).unwrap()
}

pub fn render_csv(scores: &[ProgramScore], mobility_flags: &[bool]) -> String {
    let mut lines = vec!["handle,name,total,bounty,response,scope,health,android,mobility".to_string()];
    for (s, &is_mobility) in scores.iter().zip(mobility_flags.iter()) {
        lines.push(format!(
            "{},{},{:.1},{:.0},{:.0},{:.0},{:.0},{},{}",
            s.handle, s.name, s.total, s.bounty_score, s.response_score,
            s.scope_score, s.health_score, s.has_android, is_mobility
        ));
    }
    lines.join("\n")
}
