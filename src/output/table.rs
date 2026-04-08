use tabled::{Table, Tabled};
use crate::scorer::engine::ProgramScore;

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "Program")]
    program: String,
    #[tabled(rename = "Score")]
    score: String,
    #[tabled(rename = "Bounty")]
    bounty: String,
    #[tabled(rename = "Web")]
    web: String,
    #[tabled(rename = "Health")]
    health: String,
    #[tabled(rename = "Resp")]
    resp: String,
    #[tabled(rename = "Diff")]
    difficulty: String,
    #[tabled(rename = "Scopes")]
    scopes: String,
}

pub fn render_table(scores: &[ProgramScore]) -> String {
    let rows: Vec<Row> = scores
        .iter()
        .map(|s| Row {
            program: format!("{} ({})", s.name, s.handle),
            score: format!("{:.1}", s.total),
            bounty: format!("{:.0}", s.bounty_score),
            web: format!("{:.0}", s.web_scope_score),
            health: format!("{:.0}", s.health_score),
            resp: format!("{:.0}", s.response_score),
            difficulty: format!("{:.0}", s.difficulty_score),
            scopes: format!("{}", s.web_scope_count),
        })
        .collect();

    Table::new(rows).to_string()
}
