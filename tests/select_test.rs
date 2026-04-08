use h1scout::select::{make_project_id, filter_web_scopes, split_identifiers};
use h1scout::api::models::{ScopeData, ScopeAttributes};

fn make_scope(asset_type: &str, identifier: &str, bounty: bool, submission: bool, instruction: Option<&str>) -> ScopeData {
    ScopeData {
        id: format!("s_{}", identifier.replace('.', "_")),
        data_type: "structured-scope".to_string(),
        attributes: ScopeAttributes {
            asset_type: asset_type.to_string(),
            asset_identifier: identifier.to_string(),
            eligible_for_bounty: bounty,
            eligible_for_submission: submission,
            max_severity: Some("critical".to_string()),
            instruction: instruction.map(|s| s.to_string()),
        },
    }
}

#[test]
fn test_project_id_format() {
    let project_id = make_project_id("playtika");
    assert!(project_id.starts_with("playtika_"));
    // playtika_ (9 chars) + YYYYMMDD (8 chars) = 17
    assert_eq!(project_id.len(), "playtika_".len() + 8);
}

#[test]
fn test_scope_csv_web_only() {
    let scopes = vec![
        make_scope("WILDCARD", "*.example.com", true, true, None),
        make_scope("URL", "https://api.example.com", true, true, None),
        make_scope("GOOGLE_PLAY_APP_ID", "com.example.app", true, true, None),
        make_scope("APPLE_STORE_APP_ID", "com.example.ios", true, true, None),
        make_scope("ANDROID", "com.example.android", true, true, None),
        // not eligible for bounty
        make_scope("URL", "https://staging.example.com", false, true, None),
        // not eligible for submission
        make_scope("URL", "https://internal.example.com", true, false, None),
    ];

    let web = filter_web_scopes(&scopes);
    // Only WILDCARD + first URL should pass (bounty=true, submission=true, web type)
    assert_eq!(web.len(), 2);
    assert!(web.iter().any(|w| w.identifier == "*.example.com"));
    assert!(web.iter().any(|w| w.identifier == "https://api.example.com"));
}

#[test]
fn test_scope_csv_instruction_parsing() {
    let scopes = vec![
        make_scope("URL", "https://good.example.com", true, true, None),
        make_scope("URL", "https://bad1.example.com", true, true, Some("This is out of scope for testing")),
        make_scope("URL", "https://bad2.example.com", true, true, Some("Do not test this endpoint")),
        make_scope("URL", "https://ok.example.com", true, true, Some("Please test thoroughly")),
    ];

    let web = filter_web_scopes(&scopes);
    assert_eq!(web.len(), 2);
    assert!(web.iter().any(|w| w.identifier == "https://good.example.com"));
    assert!(web.iter().any(|w| w.identifier == "https://ok.example.com"));
}

#[test]
fn test_multi_identifier_split() {
    let identifiers = "a.com,b.com,c.com";
    let result = split_identifiers(identifiers);
    assert_eq!(result, vec!["a.com", "b.com", "c.com"]);
}

#[test]
fn test_single_identifier_no_split() {
    let result = split_identifiers("example.com");
    assert_eq!(result, vec!["example.com"]);
}
