use crate::api::models::{ProgramData, ScopeData};

const MOBILITY_KEYWORDS: &[&str] = &[
    "motor", "vehicle", "car", "auto", "drive", "fleet", "telematics",
    "mobility", "transport", "uber", "lyft", "grab", "ford", "gm",
    "toyota", "honda", "bmw", "mercedes", "volkswagen", "tesla",
    "rivian", "cruise", "waymo", "argo",
];

pub fn is_mobility_target(program: &ProgramData, scopes: &[ScopeData]) -> bool {
    let name_lower = program.attributes.name.to_lowercase();
    let handle_lower = program.attributes.handle.to_lowercase();

    for kw in MOBILITY_KEYWORDS {
        if name_lower.contains(kw) || handle_lower.contains(kw) {
            return true;
        }
    }

    for scope in scopes {
        let id_lower = scope.attributes.asset_identifier.to_lowercase();
        for kw in MOBILITY_KEYWORDS {
            if id_lower.contains(kw) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::*;

    fn make_program(name: &str) -> ProgramData {
        ProgramData {
            id: "1".to_string(),
            data_type: "program".to_string(),
            attributes: ProgramAttributes {
                handle: name.to_lowercase().replace(' ', "-"),
                name: name.to_string(),
                offers_bounties: true,
                submission_state: "open".to_string(),
                fast_payments: true,
                open_scope: false,
            },
        }
    }

    fn make_scope(identifier: &str) -> ScopeData {
        ScopeData {
            id: "s1".to_string(),
            data_type: "structured-scope".to_string(),
            attributes: ScopeAttributes {
                asset_type: "URL".to_string(),
                asset_identifier: identifier.to_string(),
                eligible_for_bounty: true,
                eligible_for_submission: true,
                max_severity: Some("critical".to_string()),
                instruction: None,
            },
        }
    }

    #[test]
    fn test_match_by_program_name() {
        let program = make_program("General Motors");
        assert!(is_mobility_target(&program, &[]));
    }

    #[test]
    fn test_match_by_scope_identifier() {
        let program = make_program("SomeCorp");
        let scopes = vec![make_scope("telematics.example.com")];
        assert!(is_mobility_target(&program, &scopes));
    }

    #[test]
    fn test_no_false_positive() {
        let program = make_program("Airbnb");
        let scopes = vec![make_scope("*.airbnb.com")];
        assert!(!is_mobility_target(&program, &scopes));
    }
}
