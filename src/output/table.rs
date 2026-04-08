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
    #[tabled(rename = "Resp")]
    resp: String,
    #[tabled(rename = "Scope")]
    scope: String,
    #[tabled(rename = "Android")]
    android: String,
    #[tabled(rename = "Mobility")]
    mobility: String,
}

pub fn render_table(scores: &[ProgramScore], mobility_flags: &[bool]) -> String {
    let rows: Vec<Row> = scores
        .iter()
        .zip(mobility_flags.iter())
        .map(|(s, &is_mobility)| Row {
            program: format!("{} ({})", s.name, s.handle),
            score: format!("{:.1}", s.total),
            bounty: format!("{:.0}", s.bounty_score),
            resp: format!("{:.0}", s.response_score),
            scope: format!("{:.0}", s.scope_score),
            android: if s.has_android { "Y".into() } else { "N".into() },
            mobility: if is_mobility { "Y".into() } else { "N".into() },
        })
        .collect();

    Table::new(rows).to_string()
}
