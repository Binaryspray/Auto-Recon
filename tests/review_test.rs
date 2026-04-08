use h1scout::recon::{ReconResult, BbpInfo, ScopeInfo, TargetInfo, AttackPoint, Evidence};
use h1scout::review::{format_ap_display, generate_solve_input};

#[test]
fn test_rr_loading() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("test_20260408");
    std::fs::create_dir_all(&project_dir).unwrap();

    let rr = ReconResult {
        project_id: "test_20260408".to_string(),
        bbp: BbpInfo {
            platform: "hackerone".to_string(),
            handle: "test".to_string(),
            name: "Test".to_string(),
            score: 85.0,
        },
        scope: ScopeInfo {
            identifier: "*.test.com".to_string(),
            asset_type: "WILDCARD".to_string(),
            eligible_for_bounty: true,
            max_severity: Some("critical".to_string()),
            instruction: None,
            availability_requirement: None,
            confidentiality_requirement: None,
            integrity_requirement: None,
        },
        target: TargetInfo {
            subdomain: "api.test.com".to_string(),
            ip: None,
            tech_stack: vec![],
            status_code: 200,
            title: None,
        },
        attack_points: vec![
            AttackPoint {
                ap_id: "ap_001".to_string(),
                url: "https://api.test.com/v1/users/123".to_string(),
                method: "GET".to_string(),
                category: "idor_candidate".to_string(),
                priority: 1,
                evidence: Evidence {
                    source: "gau".to_string(),
                    raw: "/v1/users/123".to_string(),
                    llm_reasoning: None,
                },
                request_sample: None,
            },
            AttackPoint {
                ap_id: "ap_002".to_string(),
                url: "https://api.test.com/swagger".to_string(),
                method: "GET".to_string(),
                category: "exposure".to_string(),
                priority: 2,
                evidence: Evidence {
                    source: "nuclei".to_string(),
                    raw: "swagger-api".to_string(),
                    llm_reasoning: None,
                },
                request_sample: None,
            },
        ],
        created_at: "2026-04-08T00:00:00+09:00".to_string(),
    };

    std::fs::write(
        project_dir.join("RR.json"),
        serde_json::to_string_pretty(&rr).unwrap(),
    ).unwrap();

    // Load and verify
    let content = std::fs::read_to_string(project_dir.join("RR.json")).unwrap();
    let parsed: ReconResult = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed.attack_points.len(), 2);
    assert_eq!(parsed.attack_points[0].ap_id, "ap_001");
}

#[test]
fn test_ap_display_format() {
    let ap = AttackPoint {
        ap_id: "ap_001".to_string(),
        url: "https://api.test.com/v1/users/123".to_string(),
        method: "GET".to_string(),
        category: "idor_candidate".to_string(),
        priority: 1,
        evidence: Evidence {
            source: "gau".to_string(),
            raw: "/v1/users/123".to_string(),
            llm_reasoning: Some("LLM inferred".to_string()),
        },
        request_sample: None,
    };

    let display = format_ap_display(&ap);
    assert!(display.contains("[1]"));
    assert!(display.contains("idor_candidate"));
    assert!(display.contains("https://api.test.com/v1/users/123"));
}

#[test]
fn test_solve_output_format() {
    let rr = ReconResult {
        project_id: "test_20260408".to_string(),
        bbp: BbpInfo {
            platform: "hackerone".to_string(),
            handle: "test".to_string(),
            name: "Test".to_string(),
            score: 85.0,
        },
        scope: ScopeInfo {
            identifier: "*.test.com".to_string(),
            asset_type: "WILDCARD".to_string(),
            eligible_for_bounty: true,
            max_severity: Some("critical".to_string()),
            instruction: None,
            availability_requirement: None,
            confidentiality_requirement: None,
            integrity_requirement: None,
        },
        target: TargetInfo {
            subdomain: "api.test.com".to_string(),
            ip: None,
            tech_stack: vec![],
            status_code: 200,
            title: None,
        },
        attack_points: vec![AttackPoint {
            ap_id: "ap_001".to_string(),
            url: "https://api.test.com/v1/users/123".to_string(),
            method: "GET".to_string(),
            category: "idor_candidate".to_string(),
            priority: 1,
            evidence: Evidence {
                source: "gau".to_string(),
                raw: "/v1/users/123".to_string(),
                llm_reasoning: None,
            },
            request_sample: None,
        }],
        created_at: "2026-04-08T00:00:00+09:00".to_string(),
    };

    let selected = vec![0usize];
    let output = generate_solve_input(&rr, &selected);

    // Must contain required fields
    assert!(output.contains("project_id"));
    assert!(output.contains("test_20260408"));
    assert!(output.contains("ap_id"));
    assert!(output.contains("ap_001"));
    assert!(output.contains("target"));
}
