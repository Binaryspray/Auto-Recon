use crate::api::models::{ProgramData, ScopeData};
use super::weights::Weights;

#[derive(Debug, Clone)]
pub struct ProgramScore {
    pub handle: String,
    pub name: String,
    pub bounty_score: f64,
    pub web_scope_score: f64,
    pub health_score: f64,
    pub response_score: f64,
    pub difficulty_score: f64,
    pub total: f64,
    pub web_scope_count: usize,
}

/// Count web-eligible scopes (WILDCARD or URL, eligible_for_bounty + eligible_for_submission)
fn web_eligible_scopes(scopes: &[ScopeData]) -> Vec<&ScopeData> {
    scopes
        .iter()
        .filter(|s| {
            (s.attributes.asset_type == "WILDCARD" || s.attributes.asset_type == "URL")
                && s.attributes.eligible_for_bounty
                && s.attributes.eligible_for_submission
        })
        .collect()
}

/// Extract unique root domains from web scopes
fn count_root_domains(web_scopes: &[&ScopeData]) -> usize {
    let mut domains: Vec<String> = web_scopes
        .iter()
        .map(|s| {
            let id = s.attributes.asset_identifier.trim_start_matches("*.");
            let id = id.trim_start_matches("https://").trim_start_matches("http://");
            // Take last two parts as root domain
            let parts: Vec<&str> = id.split('.').collect();
            if parts.len() >= 2 {
                format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
            } else {
                id.to_string()
            }
        })
        .collect();
    domains.sort();
    domains.dedup();
    domains.len()
}

pub fn score_program(program: &ProgramData, scopes: &[ScopeData], weights: &Weights) -> ProgramScore {
    let attrs = &program.attributes;
    let web_scopes = web_eligible_scopes(scopes);
    let web_scope_count = web_scopes.len();

    // ── bounty_score (0~100) ──
    // offers_bounties +50, fast_payments +30, open_scope +20
    let mut bounty_score = 0.0;
    if attrs.offers_bounties {
        bounty_score += 50.0;
    }
    if attrs.fast_payments {
        bounty_score += 30.0;
    }
    if attrs.open_scope {
        bounty_score += 20.0;
    }

    // ── web_scope_score (0~100) ──
    // web eligible count × 8 (max 40) + WILDCARD +25 + critical severity +15
    // + no instruction ratio > 50% → +10 + multiple root domains +10
    let mut web_scope_score = (web_scope_count as f64 * 8.0).min(40.0);

    let has_wildcard = web_scopes.iter().any(|s| s.attributes.asset_identifier.contains('*'));
    if has_wildcard {
        web_scope_score += 25.0;
    }

    let has_critical = web_scopes.iter().any(|s| {
        s.attributes.max_severity.as_deref() == Some("critical")
    });
    if has_critical {
        web_scope_score += 15.0;
    }

    let no_instruction_count = web_scopes.iter().filter(|s| s.attributes.instruction.is_none()).count();
    if web_scope_count > 0 && no_instruction_count * 2 > web_scope_count {
        web_scope_score += 10.0;
    }

    let root_domain_count = count_root_domains(&web_scopes);
    if root_domain_count >= 2 {
        web_scope_score += 10.0;
    }

    web_scope_score = web_scope_score.clamp(0.0, 100.0);

    // ── health_score (0~100) ──
    // open +50, offers_bounties +20, open_scope +20, fast_payments +10
    let mut health_score = 0.0;
    if attrs.submission_state == "open" {
        health_score += 50.0;
    }
    if attrs.offers_bounties {
        health_score += 20.0;
    }
    if attrs.open_scope {
        health_score += 20.0;
    }
    if attrs.fast_payments {
        health_score += 10.0;
    }

    // ── response_score (0~100) ──
    // fast_payments → 80, else → 30
    let response_score = if attrs.fast_payments { 80.0 } else { 30.0 };

    // ── difficulty_score (0~100, higher = easier target) ──
    // WILDCARD only (no URL detail) +25, instruction-free > 50% +20,
    // scope count >= 10 +20, open_scope +15, !fast_payments +20
    let mut difficulty_score: f64 = 0.0;

    let has_url_scope = web_scopes.iter().any(|s| s.attributes.asset_type == "URL");
    if has_wildcard && !has_url_scope {
        // Only wildcards, no specific URLs = less mature security
        difficulty_score += 25.0;
    }

    if web_scope_count > 0 && no_instruction_count * 2 > web_scope_count {
        difficulty_score += 20.0;
    }

    if web_scope_count >= 10 {
        difficulty_score += 20.0;
    }

    if attrs.open_scope {
        difficulty_score += 15.0;
    }

    if !attrs.fast_payments {
        // Slow payments = possibly immature security team
        difficulty_score += 20.0;
    }

    difficulty_score = difficulty_score.clamp(0.0, 100.0);

    // ── total ──
    let total = (bounty_score * weights.bounty_scale
        + web_scope_score * weights.web_scope
        + health_score * weights.program_health
        + response_score * weights.response_speed
        + difficulty_score * weights.difficulty)
        .clamp(0.0, 100.0);

    ProgramScore {
        handle: attrs.handle.clone(),
        name: attrs.name.clone(),
        bounty_score,
        web_scope_score,
        health_score,
        response_score,
        difficulty_score,
        total,
        web_scope_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::*;

    fn make_program(handle: &str, name: &str, offers_bounties: bool, submission_state: &str, fast_payments: bool, open_scope: bool) -> ProgramData {
        ProgramData {
            id: "1".to_string(),
            data_type: "program".to_string(),
            attributes: ProgramAttributes {
                handle: handle.to_string(),
                name: name.to_string(),
                offers_bounties,
                submission_state: submission_state.to_string(),
                fast_payments,
                open_scope,
            },
        }
    }

    fn make_scope(asset_type: &str, identifier: &str, eligible: bool, severity: &str, instruction: Option<&str>) -> ScopeData {
        ScopeData {
            id: format!("s_{}", identifier.replace('.', "_")),
            data_type: "structured-scope".to_string(),
            attributes: ScopeAttributes {
                asset_type: asset_type.to_string(),
                asset_identifier: identifier.to_string(),
                eligible_for_bounty: eligible,
                eligible_for_submission: true,
                max_severity: Some(severity.to_string()),
                instruction: instruction.map(|s| s.to_string()),
            },
        }
    }

    #[test]
    fn test_wildcard_gives_high_web_scope() {
        let program = make_program("test", "Test Corp", true, "open", true, false);
        let scopes = vec![
            make_scope("WILDCARD", "*.test.com", true, "critical", None),
            make_scope("URL", "api.test.com", true, "high", None),
            make_scope("URL", "app.test.com", true, "high", None),
        ];
        let weights = Weights::default();
        let score = score_program(&program, &scopes, &weights);
        // 3 web × 8 = 24 + WILDCARD 25 + critical 15 + no_instruction 10 = 74
        assert!(score.web_scope_score >= 70.0, "web_scope_score was {}", score.web_scope_score);
    }

    #[test]
    fn test_no_web_scope_gives_zero() {
        let program = make_program("mobile", "Mobile Only", true, "open", true, false);
        let scopes = vec![
            make_scope("ANDROID", "com.example.app", true, "critical", None),
            make_scope("APPLE_STORE_APP_ID", "com.example.ios", true, "high", None),
        ];
        let weights = Weights::default();
        let score = score_program(&program, &scopes, &weights);
        assert_eq!(score.web_scope_score, 0.0);
        assert_eq!(score.web_scope_count, 0);
    }

    #[test]
    fn test_closed_program_low_health() {
        let program = make_program("closed", "Closed Program", true, "closed", false, false);
        let scopes = vec![];
        let weights = Weights::default();
        let score = score_program(&program, &scopes, &weights);
        assert!(score.health_score <= 20.0, "health_score was {}", score.health_score);
    }

    #[test]
    fn test_immature_program_high_difficulty() {
        // No fast_payments, open_scope, wildcard only, many scopes, no instructions
        let program = make_program("easy", "Easy Target", true, "open", false, true);
        let mut scopes = vec![
            make_scope("WILDCARD", "*.easy.com", true, "critical", None),
        ];
        for i in 0..10 {
            scopes.push(make_scope("WILDCARD", &format!("*.sub{}.easy.com", i), true, "high", None));
        }
        let weights = Weights::default();
        let score = score_program(&program, &scopes, &weights);
        // wildcard_only +25 + no_instruction +20 + scope>=10 +20 + open_scope +15 + !fast_payments +20 = 100
        assert!(score.difficulty_score >= 80.0, "difficulty_score was {}", score.difficulty_score);
    }

    #[test]
    fn test_mature_program_low_difficulty() {
        // fast_payments, not open_scope, few scopes with instructions
        let program = make_program("hard", "Hard Target", true, "open", true, false);
        let scopes = vec![
            make_scope("URL", "https://api.hard.com", true, "critical", Some("Only test auth endpoints")),
            make_scope("URL", "https://app.hard.com", true, "high", Some("No automated scanning")),
        ];
        let weights = Weights::default();
        let score = score_program(&program, &scopes, &weights);
        // No wildcard_only, no instruction-free majority, scope<10, no open_scope, fast_payments
        assert!(score.difficulty_score <= 20.0, "difficulty_score was {}", score.difficulty_score);
    }

    #[test]
    fn test_multiple_root_domains_bonus() {
        let program = make_program("multi", "Multi Domain", true, "open", true, false);
        let scopes = vec![
            make_scope("WILDCARD", "*.example.com", true, "critical", None),
            make_scope("WILDCARD", "*.example.org", true, "high", None),
            make_scope("URL", "https://api.other.io", true, "high", None),
        ];
        let weights = Weights::default();
        let score = score_program(&program, &scopes, &weights);
        // 3 domains → multi-domain bonus +10
        assert!(score.web_scope_score >= 70.0, "web_scope_score was {}", score.web_scope_score);
    }

    #[test]
    fn test_all_scores_in_bounds() {
        let program = make_program("test", "Test", true, "open", true, true);
        let scopes = vec![make_scope("URL", "*.test.com", true, "critical", None)];
        let weights = Weights::default();
        let score = score_program(&program, &scopes, &weights);
        assert!(score.bounty_score >= 0.0 && score.bounty_score <= 100.0);
        assert!(score.web_scope_score >= 0.0 && score.web_scope_score <= 100.0);
        assert!(score.health_score >= 0.0 && score.health_score <= 100.0);
        assert!(score.response_score >= 0.0 && score.response_score <= 100.0);
        assert!(score.difficulty_score >= 0.0 && score.difficulty_score <= 100.0);
        assert!(score.total >= 0.0 && score.total <= 100.0);
    }

    #[test]
    fn test_sort_order() {
        let weights = Weights::default();
        // p1: best — bounties, fast, open_scope, many web scopes
        let p1 = make_program("a", "A", true, "open", true, true);
        // p2: mid
        let p2 = make_program("b", "B", true, "open", false, false);
        // p3: worst — closed, no bounties
        let p3 = make_program("c", "C", false, "closed", false, false);

        let s1 = vec![
            make_scope("WILDCARD", "*.a.com", true, "critical", None),
            make_scope("URL", "https://api.a.com", true, "high", None),
        ];
        let s2 = vec![make_scope("URL", "*.b.com", true, "medium", None)];
        let s3 = vec![];

        let mut scores = vec![
            score_program(&p1, &s1, &weights),
            score_program(&p2, &s2, &weights),
            score_program(&p3, &s3, &weights),
        ];
        scores.sort_by(|a, b| b.total.partial_cmp(&a.total).unwrap());
        assert!(scores[0].total >= scores[1].total);
        assert!(scores[1].total >= scores[2].total);
    }
}
