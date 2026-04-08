use crate::api::models::{ProgramData, ScopeData};
use super::weights::Weights;

#[derive(Debug, Clone)]
pub struct ProgramScore {
    pub handle: String,
    pub name: String,
    pub bounty_score: f64,
    pub response_score: f64,
    pub scope_score: f64,
    pub health_score: f64,
    pub total: f64,
    pub has_android: bool,
}

pub fn score_program(program: &ProgramData, scopes: &[ScopeData], weights: &Weights) -> ProgramScore {
    let attrs = &program.attributes;

    let mut bounty_score = 0.0;
    if attrs.offers_bounties {
        bounty_score += 60.0;
    }
    if attrs.fast_payments {
        bounty_score += 40.0;
    }

    let response_score = if attrs.fast_payments { 80.0 } else { 40.0 };

    let eligible_count = scopes.iter().filter(|s| s.attributes.eligible_for_bounty).count();
    let mut scope_score = (eligible_count as f64 * 5.0).min(60.0);

    let has_android = scopes.iter().any(|s| s.attributes.asset_type == "ANDROID");
    if has_android {
        scope_score += 20.0;
    }

    let has_wildcard = scopes.iter().any(|s| s.attributes.asset_identifier.contains('*'));
    if has_wildcard {
        scope_score += 10.0;
    }

    let mobility_keywords = ["vehicle", "car", "auto", "motor", "drive", "fleet", "telematics", "mobility", "transport"];
    let has_mobility = scopes.iter().any(|s| {
        let id_lower = s.attributes.asset_identifier.to_lowercase();
        mobility_keywords.iter().any(|kw| id_lower.contains(kw))
    });
    if has_mobility {
        scope_score += 15.0;
    }
    scope_score = scope_score.clamp(0.0, 100.0);

    let mut health_score = 0.0;
    if attrs.submission_state == "open" {
        health_score += 40.0;
    }
    if attrs.fast_payments {
        health_score += 30.0;
    }
    if attrs.open_scope {
        health_score += 20.0;
    }
    if attrs.offers_bounties {
        health_score += 10.0;
    }

    let total = (bounty_score * weights.bounty_scale
        + response_score * weights.response_speed
        + scope_score * weights.scope_quality
        + health_score * weights.program_health)
        .clamp(0.0, 100.0);

    ProgramScore {
        handle: attrs.handle.clone(),
        name: attrs.name.clone(),
        bounty_score,
        response_score,
        scope_score,
        health_score,
        total,
        has_android,
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

    fn make_scope(asset_type: &str, identifier: &str, eligible: bool) -> ScopeData {
        ScopeData {
            id: "s1".to_string(),
            data_type: "structured-scope".to_string(),
            attributes: ScopeAttributes {
                asset_type: asset_type.to_string(),
                asset_identifier: identifier.to_string(),
                eligible_for_bounty: eligible,
                eligible_for_submission: true,
                max_severity: Some("critical".to_string()),
                instruction: None,
            },
        }
    }

    #[test]
    fn test_android_scope_gives_bonus() {
        let program = make_program("gm", "General Motors", true, "open", true, false);
        let scopes = vec![
            make_scope("ANDROID", "com.gm.myvehicle", true),
            make_scope("URL", "*.gm.com", true),
            make_scope("URL", "api.gm.com", true),
            make_scope("URL", "fleet.gm.com", true),
            make_scope("URL", "dealer.gm.com", true),
            make_scope("URL", "auth.gm.com", true),
            make_scope("URL", "portal.gm.com", true),
        ];
        let weights = Weights::default();
        let score = score_program(&program, &scopes, &weights);
        assert!(score.scope_score >= 80.0, "scope_score was {}", score.scope_score);
        assert!(score.has_android);
    }

    #[test]
    fn test_closed_program_low_health() {
        let program = make_program("closed", "Closed Program", true, "closed", false, false);
        let scopes = vec![];
        let weights = Weights::default();
        let score = score_program(&program, &scopes, &weights);
        assert!(score.health_score <= 10.0, "health_score was {}", score.health_score);
    }

    #[test]
    fn test_all_scores_in_bounds() {
        let program = make_program("test", "Test", true, "open", true, true);
        let scopes = vec![make_scope("URL", "*.test.com", true)];
        let weights = Weights::default();
        let score = score_program(&program, &scopes, &weights);
        assert!(score.bounty_score >= 0.0 && score.bounty_score <= 100.0);
        assert!(score.response_score >= 0.0 && score.response_score <= 100.0);
        assert!(score.scope_score >= 0.0 && score.scope_score <= 100.0);
        assert!(score.health_score >= 0.0 && score.health_score <= 100.0);
        assert!(score.total >= 0.0 && score.total <= 100.0);
    }

    #[test]
    fn test_sort_order() {
        let weights = Weights::default();
        let p1 = make_program("a", "A", true, "open", true, true);
        let p2 = make_program("b", "B", true, "open", false, false);
        let p3 = make_program("c", "C", false, "closed", false, false);

        let s1 = vec![make_scope("ANDROID", "com.a.app", true), make_scope("URL", "*.a.com", true)];
        let s2 = vec![make_scope("URL", "*.b.com", true)];
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
